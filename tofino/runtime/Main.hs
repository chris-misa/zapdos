{-
 - Runtime controler for ZAPDOS tofino
 -
 - Author: Chris Misa
 - Date: 2024-05-21
 -
 - See ../../LICENSE for conditions.
 -
 - Notes:
 - 
 - Must be run with +RTS -N16 or something like that
 - 
 - Manual config steps:
 - 
 - expand kernel recv memory buffer
 - set address on linux side of CPU iface (normally 192.168.1.100/24 so that it routes to 192.168.1.1 used as switch side target
 - add arp entry for switch side address (192.168.1.1) with bogus mac address (e.g., 00:01:02:03:04:05)
 - 
 - Non-trivial implementation bits:
 - 
 - * using pre-multiplied lookup to compute indexes for childbitmap.
 - * using same Bloom filter for lookback32 to compute benign traffic profile by switch hardware program between pre-attack and active-attack modes.
 - * using ferry packets to extract results.
 - * using clear bits to triger reset of register in data plane.
 - * approach to tuning delays to achieve desired epoch duration.
 - * threading control plan to keep expensive operations that are non-critical to feature update in background (connected with async queues).
 -   * collecting digests and updating lookback.
 -   * reporting results and updating selection TCAM.
 - 
 - Notes about things that might impact performance:
 - * Moving averages might need tuning of the LPF params to closer-approximate EWMA.
 -}


{-# LANGUAGE OverloadedLists #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE BangPatterns #-}

module Main where

import Data.Function ((&))
import Data.Text.Internal.Lazy (Text)
import Data.Word
import Data.Maybe
import Data.Bits
import qualified Data.List as L
import qualified Data.Vector as V
import qualified Control.Concurrent as CC
import Control.Concurrent.MVar
import System.Environment
import System.IO
import Control.Monad (join, when)
import Control.Arrow ((***), first, second)

import qualified Data.HashMap.Strict as M
import System.Clock
import System.Random.Mersenne.Pure64 (pureMT, PureMT)
import Immutable.Shuffle (shuffle)

import Control.DeepSeq (force)
import Data.Vector.Strategies (parVector, using)

-- Local imports
import Common
import Tofino
import qualified RandomForest as RF

timeIt :: IO () -> IO ()
timeIt a = do
  s <- getTime Monotonic
  a
  e <- getTime Monotonic
  let dt = fromIntegral (toNanoSecs $ diffTimeSpec e s) / 1000000000.0
  putStrLn $ "...took " ++ show dt ++ " seconds"

seed :: Word64
seed = 12345


data ZAPDOSState = ZAPDOSState
  { zsConfig :: ZAPDOSConfig
  , zsModelFilepath :: String
  , zsOutputFilepath :: String
  , zsMetadataFilepath :: String
  
  , zsOutputFile :: Handle
  , zsMetadataFile :: Handle
  , zsModel :: RF.RandomForest

  , zsAttackStartTime :: !TimeSpec -- real time when attack started
  , zsEpoch :: !Int                -- current epoch number
  , zsNextBatchTimes :: V.Vector TimeSpec -- next scheduled batch start times
  
  , zsCurBatch :: !Int             -- index of next batch to process
  , zsMonitoredPrefixes :: !(V.Vector (V.Vector (Int, (Prefix, Features))))

  , zsNonEmptyChildren :: !(V.Vector (Prefix, Features))
  , zsActiveHoldouts :: MaybeChan (Prefix, Features)
  , zsInactiveHoldouts :: MaybeChan (Prefix, Features)
  , zsResultsPipe :: MaybeChan (Double, (Prefix, Features))

  , zsRndState :: PureMT

  , zsNumReports :: Int
  , zsStats :: Stats

  , zsSelectTableLock :: MVar ()
  }

-- Note, some of these have to line up with the p4 program...
getZapdosState :: IO ZAPDOSState
getZapdosState = do
  activeHoldouts <- newMaybeChan
  inactiveHoldouts <- newMaybeChan
  resultsPipe <- newMaybeChan
  selectTableLock <- newMVar ()
  return ZAPDOSState
    { zsConfig = defaultZapdosConfig
    , zsModelFilepath = ""
    , zsOutputFilepath = ""
    , zsMetadataFilepath = ""
    
    , zsOutputFile = undefined
    , zsMetadataFile = undefined
    , zsModel = undefined

    , zsAttackStartTime = TimeSpec 0 0
    , zsEpoch = 0
    , zsNextBatchTimes = V.empty
    
    , zsCurBatch = 0
    , zsMonitoredPrefixes = V.empty
    
    , zsNonEmptyChildren = V.empty
    , zsActiveHoldouts = activeHoldouts
    , zsInactiveHoldouts = inactiveHoldouts
    , zsResultsPipe = resultsPipe
    
    , zsRndState = pureMT seed

    , zsNumReports = 0
    , zsStats = zeroStats

    , zsSelectTableLock = selectTableLock
    }

--
-- Converts features to a flat vector for the model
--
featuresToVector :: Int -> Int -> Features -> V.Vector Double
featuresToVector p epoch f =
  let Features
        { fPktsFrom = pktsFrom
        , fPktsTo = pktsTo
        , fBytesFrom = bytesFrom
        , fBytesTo = bytesTo
        , fLastActiveEpoch = lastActiveEpoch
        , fPrevTime = prevTime
        , fMinIPG = minIPG
        , fMaxIPG = maxIPG
        , fAveIPG = aveIPG
        , fMinLen = minLen
        , fMaxLen = maxLen
        , fAveLen = aveLen
        , fRespReqList = respReqList
        } = f
      respReqDiff = computeRespReqDiff respReqList
      lastActiveDiff = epoch - lastActiveEpoch
  in V.fromList
      [ fromIntegral p
      , fromIntegral bytesFrom
      , fromIntegral bytesTo
      , fromIntegral respReqDiff
      , fromIntegral lastActiveDiff
      , minIPG
      , maxIPG
      , aveIPG
      , fromIntegral pktsFrom
      , fromIntegral pktsTo
      , minLen
      , maxLen
      , aveLen
      ]


data Stats = Stats
  { stNumRemovals :: Int
  , stNumAdditions :: Int
  , stNumZoomedIn :: Int
  , stNumPushedToHoldout :: Int
  , stNumNonEmptyChildren :: Int
  , stNumResults :: Int
  , stNumPullIns :: Int
  , stNumActivePullIns :: Int
  , stNumInactivePullIns :: Int
  , stN :: Double -- n for following means
  , stTurnaroundTimeMean :: Double -- time between collecting features and updating monitoring slots mean over all batches in epoch
  , stResultReqTimeMean :: Double -- time spent collecting results mean over all batches in epoch
  , stHWUpdateTimeMean :: Double -- time spent updating selection tables in hardware mean over all batches in epoch
  , stModelApplicationTimeMean :: Double -- time spent applying model to features collected from data plane
  , stPullHoldoutsTimeMean :: Double -- time spent pulling from holdout queues from lookback process
  , stPushHoldoutsTimeMean :: Double -- time spent pushing to inactive holdouts queue
  , stResultUpdateTimeMean :: Double -- time spent writting detected prefixes into selection TCAM
  } deriving (Show)

zeroStats :: Stats
zeroStats = Stats 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

statsHeader :: String
statsHeader = "curTime,epoch,prefixesPerEpoch,batchSize,removals,additions,zoomedIn,pushedToHoldout,nonEmptyChildren,numResults,numPullIns,activePullIns,inactivePullIns,n,turnaroundTimeMean,resultReqTimeMean,hwUpdateTimeMean,modelApplicationTimeMean,pullHoldoutsTimeMean,pushHoldoutsTimeMean,resultUpdateTimeMean"

statsToList :: ZAPDOSState -> Double -> Stats -> [String]
statsToList state curTime stats =
  [ show $ curTime
  , show $ zsEpoch state
  , show $ confPrefixesPerEpoch $ zsConfig state
  , show $ confBatchSize $ zsConfig state
  , show $ stNumRemovals stats
  , show $ stNumAdditions stats
  , show $ stNumZoomedIn stats
  , show $ stNumPushedToHoldout stats
  , show $ stNumNonEmptyChildren stats
  , show $ stNumResults stats
  , show $ stNumPullIns stats
  , show $ stNumActivePullIns stats
  , show $ stNumInactivePullIns stats
  , show $ stN stats
  , show $ stTurnaroundTimeMean stats
  , show $ stResultReqTimeMean stats
  , show $ stHWUpdateTimeMean stats
  , show $ stModelApplicationTimeMean stats
  , show $ stPullHoldoutsTimeMean stats
  , show $ stPushHoldoutsTimeMean stats
  , show $ stResultUpdateTimeMean stats
  ]


-- 
-- Reset features for accumulation in next epoch
-- Note that this is where we update lastActiveEpoch
--
resetFeatures :: Int -> (Prefix, Features) -> (Prefix, Features)
resetFeatures epoch (p, f) =
  let lastActiveEpoch =
        if not (featuresIsZero f)
        then epoch
        else fLastActiveEpoch f
      f' = zeroFeatures
          { fLastActiveEpoch = lastActiveEpoch
          , fPrevTime = fPrevTime f
          , fScore = fScore f
          , fChildBitmap = fChildBitmap f
          }
  in (p, f')

initPrefixes :: ZAPDOSConfig -> V.Vector (Prefix, Features)
initPrefixes conf =
  let nActive = 2 ^ confInitDepth conf
  in V.generate nActive genOne
  where genOne :: Int -> (Prefix, Features)
        genOne i =
          let k = fromIntegral i `shiftL` (32 - confInitDepth conf)
          in (Prefix k (confInitDepth conf), zeroFeatures)

initialLookbacks :: ZAPDOSConfig -> V.Vector PrefixMap
initialLookbacks conf =
  let n = 32 `div` confBitsPerEpoch conf
  in V.replicate n M.empty

-- Note that this does not preserve the mapped values (can't replace filloutPrefixMap uses for benign prox!)
computeAllLookbacks :: ZAPDOSConfig -> PrefixMap -> V.Vector PrefixMap
computeAllLookbacks conf pm =
  [(32 - (confBitsPerEpoch conf)), (32 - 2 * (confBitsPerEpoch conf)) .. 0]
  & reverse
  & foldl oneLength [pm]
  & V.fromList
  where oneLength (prev : theRest) l =
          let next = M.mapKeys (\(Prefix k p) -> Prefix (maskForBits l .&. k) l) prev
          in next : prev : theRest

--
-- lookbackLoop and activeAttackLoop run in parallel.
-- They exchange information about active and in-active held-out prefixes as shown below.
-- Concurrent queues (based on unagi-chan, but wrapped for easier read behavior) which support multiple readers and writers to handle this communication efficiently.
--
--     +-------------------------------------------------------------+
--     |                                                             |
--     V                                                             ^
-- main thread <--- active holdouts <--- lookback thread <--- inactive holdouts
--     V                                            V                ^  ^
--     |                                            |                |  |
--     |                                            +----------------+  |
--     +----------------------------------------------------------------+
--
lookbackLoop :: ZAPDOSState -> TofinoState -> IO ()
lookbackLoop state ts = do
  let conf = zsConfig state
      timeout = 3600

  killSwitch <- newEmptyMVar -- unused for now because this is infinite loop...
  activeLookback <- newEmptyMVar

  CC.forkIO $ collectPrefixMap conf ts timeout killSwitch activeLookback

  let loop rndState = do

        CC.threadDelay (round (confEpochDuration conf * 1000000))

        cur <- takeMVar activeLookback
        putMVar activeLookback M.empty
        clearLookback ts

        let !newLookbacks = cur -- computeAllLookbacks conf cur

        -- Read all inactive holdouts
        let pullAllInactives xs = do
              xM <- readMaybeChan (zsInactiveHoldouts state)
              case xM of
                Just x -> pullAllInactives (x : xs)
                Nothing -> return xs
        oldInactives <- pullAllInactives []

        -- partition based on lookups in newLookbacks
        let wasActive (Prefix k p, f) =
              -- let a = M.member (Prefix k p) (newLookbacks V.! (p `div` confBitsPerEpoch conf))
              let a = M.member (Prefix k p) newLookbacks
              in (a, (Prefix k p, zeroFeatures { fScore = fScore f }))
        
        let (actives, inactives) = oldInactives
                                 & fmap wasActive
                                 & L.partition fst
                                 & join (***) (fmap snd)

        let (inactivesShuf, rndState') = shuffle (V.fromList inactives) rndState & first V.toList -- originally these were all vectors...if the conversion is too much overhead, probably can shuffle the list directly?
        
        -- push to active and inactive holdouts based on partitioning
        sequence $ fmap (writeMaybeChan (zsActiveHoldouts state)) actives
        sequence $ fmap (writeMaybeChan (zsInactiveHoldouts state)) inactivesShuf
        
        loop rndState'
  loop (pureMT seed)


judgePrefix ::
     ZAPDOSState
  -> Int
  -> PrefixMap
  -> (Prefix, Features)
  -> (Prefix, Features)
judgePrefix state epoch benignPrefixes (Prefix k p, f)
  | fPktsFrom f == 0 || fMinIPG f == (-1.0) =
      let f' = f { fZoomDecision = False }
      in (Prefix k p, f')
  | otherwise = 
      let fVec = featuresToVector p epoch f
          resp = RF.predict fVec (zsModel state)
          zoomDecision = resp >= confZoomInThreshold conf
          reportDecision = zoomDecision &&
            (p >= 32 || getBenignProx benignPrefixes (Prefix k p) <= confBenignProxThresh conf)
          f' = f
              { fZoomDecision = zoomDecision
              , fReportDecision = reportDecision
              , fScore = resp
              }
      in (Prefix k p, f')
      where conf = zsConfig state

zoomIn :: Int -> (Prefix, Features) -> V.Vector (Prefix, Features)
zoomIn n (Prefix k p, f) =
  V.generate (2 ^ n) genOne
  where genOne :: Int -> (Prefix, Features)
        genOne i =
          let k' = k .|. fromIntegral (i `shiftL` (32 - (p + n)))
              activeChild = fChildBitmap f .&. (1 `shiftL` i) /= 0
          in (Prefix k' (p + n), f { fActiveChild = activeChild })


activeAttackLoop :: ZAPDOSState -> TofinoState -> PrefixMap -> IO ()
activeAttackLoop oldState ts benignPrefixMap = do
  let conf = zsConfig oldState
      curBatch = zsCurBatch oldState

      epochDur = fromNanoSecs (round (1000000000.0 * confEpochDuration conf))

  waitStart <- getTime Monotonic
  let waitEnd = zsNextBatchTimes oldState V.! curBatch
      wait = do
        cur <- getTime Monotonic
        if cur >= waitEnd
          then return cur
          else do
          CC.threadDelay 5
          wait
          
  curTimeSpec <- wait

  -- TODO: need to think more about how time is used here compared with in simulator...
  let curTime = ((/ 1000000000.0) . fromIntegral . toNanoSecs . (diffTimeSpec (zsAttackStartTime oldState))) curTimeSpec
      nextBatchTimes = zsNextBatchTimes oldState V.// [(curBatch, waitEnd + epochDur)]

  state <-
    if curBatch == 0
    then do
      putStrLn $ "Starting epoch " ++ show (zsEpoch oldState + 1) ++ " at time = " ++ show curTime
      -- putStrLn $ "Stats: " ++ show (zsStats oldState)
      let st = oldState
               { zsEpoch = zsEpoch oldState + 1
               , zsNextBatchTimes = nextBatchTimes
               }
      printMetadata st curTime
      return $ st
        { zsStats = zeroStats
        }
    else return $ oldState { zsNextBatchTimes = nextBatchTimes }

  --
  -- Get CPU state for this batch
  --
  let batch :: V.Vector (Int, (Prefix, Features))
      batch = zsMonitoredPrefixes state V.! curBatch

      baseId = fst $ batch V.! 0
      prefixForId id = fst $ snd $ batch V.! (id - baseId)

  --
  -- Pull features for this batch
  --
  startResultReqs <- getTime Monotonic
  feats <- batch
           & V.filter (not . fIsInactive . snd . snd)
           & V.map fst
           & resultReqs ts
  endResultReqs <- getTime Monotonic

  --
  -- Judge features
  --
  let startModelApplications = endResultReqs -- don't call getTime again cause we already have it
  let !judgements = feats
        & V.map (\(i, f) -> force $ judgePrefix state (round curTime) benignPrefixMap (prefixForId i, f))
        & (`using` parVector 1)
        & force
  endModelApplications <- getTime Monotonic

  --
  -- Compute updates for this batch in next epoch
  --

  -- Pull out reports
  let !(!newReports, !preZoomIns) = V.partition (fReportDecision . snd) judgements

  -- Partition based on zoom decision (from judgement) and child state
  let !(!(!activeChildren, !inactiveChildren), !theRest) = preZoomIns
        & V.partition (fZoomDecision . snd)
        & join (***) (V.map (resetFeatures (round curTime))) -- join (***) f == (\(x, y) -> (f x, f y))
        & first (V.concatMap (zoomIn (confBitsPerEpoch conf))) -- first f == (\(x, y) -> (f x, y)) -- zoomIn sets fActiveChild...
        & first (V.partition (fActiveChild . snd))
        & first (join (***) (V.map (\(p, f) -> (p, f { fChildBitmap = 0, fActiveChild = False })))) -- have to reset the child bitmap fields before next epoch...

  -- Start batch with active children
  let !(!batchChildren, !nextChildren) = V.splitAt (confBatchSize conf) activeChildren

  -- Pull in enough extra prefixes from non-empty children, then active holdouts, then inactiveChildren ++ theRest to fill out this batch for next epoch
  let !numPullIns = max (confBatchSize conf - V.length batchChildren) 0

      (pulledInChildren, nonEmptyChildren) =  V.splitAt numPullIns (zsNonEmptyChildren state)

  startPullHoldouts <- getTime Monotonic
  let !numNewPullIns = max (numPullIns - V.length pulledInChildren) 0
  
  newPullIns <- replicate numNewPullIns (readMaybeChan $ zsActiveHoldouts state)
                & sequence
                >>= (return . V.fromList . fmap fromJust . takeWhile isJust)

  let numInactivePullIns = max (numNewPullIns - V.length newPullIns) 0

  inactivePullIns <- replicate numInactivePullIns (readMaybeChan $ zsInactiveHoldouts state)
                     & sequence
                     >>= (return . V.fromList . fmap fromJust . takeWhile isJust)

  endPullHoldouts <- getTime Monotonic

  let !(!pullIns, !inactive) = V.splitAt numPullIns (pulledInChildren V.++ newPullIns V.++ inactivePullIns V.++ inactiveChildren V.++ theRest)

      numPadding = max (numPullIns - V.length pullIns) 0
      padding = V.replicate numPadding defaultInactivePrefix

  -- Form next batch
  let !batch' = V.map fst batch `V.zip` (batchChildren V.++ pullIns V.++ padding)
      !nonEmptyChildren' = nextChildren V.++ nonEmptyChildren

  -- Push inactive to holdouts
  startPushHoldouts <- getTime Monotonic
  V.sequence $ V.map (writeMaybeChan $ zsInactiveHoldouts state) inactive
  endPushHoldouts <- getTime Monotonic

  -- Push next batch to hardware
  let !removals = batch
                 & V.filter (not . fIsInactive . snd . snd)
                 & V.map (fst . snd)
      !additions = batch'
                  & V.filter (not . fIsInactive . snd . snd)
                  & V.map (\(idx, (pfx, _)) -> (pfx, idx))

  startHWUpdate <- getTime Monotonic
  updateMonitorSlots conf ts (V.map fst newReports) removals additions
  endHWUpdate <- getTime Monotonic

  -- Report detected prefixes and add entry in selection TCAM
  -- (This has to happen after removals above because otherwise we get duplicate keys in the select_by_src TCAM)
  
  startResultUpdate <- getTime Monotonic
  V.sequence $ V.map (writeMaybeChan $ zsResultsPipe state) $ V.map (curTime,) newReports
  endResultUpdate <- getTime Monotonic

  let !stats' = (zsStats state)
                { stNumRemovals = V.length removals + (stNumRemovals $ zsStats state)
                , stNumAdditions = V.length additions + (stNumAdditions $ zsStats state)
                , stNumZoomedIn = V.length (preZoomIns & V.filter (fZoomDecision . snd)) + (stNumZoomedIn $ zsStats state)
                , stNumPushedToHoldout = V.length inactive + (stNumPushedToHoldout $ zsStats state)
                , stNumNonEmptyChildren = V.length nonEmptyChildren
                , stNumResults = V.length newReports + (stNumResults $ zsStats state)
                , stNumPullIns = numPullIns + (stNumPullIns $ zsStats state)
                , stNumActivePullIns = V.length newPullIns + (stNumActivePullIns $ zsStats state)
                , stNumInactivePullIns = V.length inactivePullIns + (stNumInactivePullIns $ zsStats state)
                }
                

  -- Update state and recurse
  let !state' = state
                { zsCurBatch = (curBatch + 1) `mod` confBatchesPerEpoch conf
                , zsMonitoredPrefixes = zsMonitoredPrefixes state V.// [(curBatch, batch')]
                , zsNonEmptyChildren = nonEmptyChildren'
                , zsNumReports = V.length newReports + zsNumReports state
                , zsStats = stats'
                }

  endTime <- getTime Monotonic
  let turnaroundTime = diffTimeSpec endTime curTimeSpec
        & toNanoSecs
        & fromIntegral
        & (/ 1000000000.0)

      resultReqTime = diffTimeSpec endResultReqs startResultReqs
        & toNanoSecs
        & fromIntegral
        & (/ 1000000000.0)

      hwUpdateTime = diffTimeSpec endHWUpdate startHWUpdate
        & toNanoSecs
        & fromIntegral
        & (/ 1000000000.0)

      modelApplicationTime = diffTimeSpec endModelApplications startModelApplications
        & toNanoSecs
        & fromIntegral
        & (/ 1000000000.0)

      pullHoldoutsTime = diffTimeSpec endPullHoldouts startPullHoldouts
        & toNanoSecs
        & fromIntegral
        & (/ 1000000000.0)

      pushHoldoutsTime = diffTimeSpec endPushHoldouts startPushHoldouts
        & toNanoSecs
        & fromIntegral
        & (/ 1000000000.0)

      resultUpdateTime = diffTimeSpec endResultUpdate startResultUpdate
        & toNanoSecs
        & fromIntegral
        & (/ 1000000000.0)

  let n = (stN $ zsStats state') + 1
      turnaroundTimeMean = (stTurnaroundTimeMean $ zsStats state') * (n - 1) / n + turnaroundTime / n
      resultReqTimeMean = (stResultReqTimeMean $ zsStats state') * (n - 1) / n + resultReqTime / n
      hwUpdateTimeMean = (stHWUpdateTimeMean $ zsStats state') * (n - 1) / n + hwUpdateTime / n
      modelApplicationTimeMean = (stModelApplicationTimeMean $ zsStats state') * (n - 1) / n + modelApplicationTime / n
      pullHoldoutsTimeMean = (stPullHoldoutsTimeMean $ zsStats state') * (n - 1) / n + pullHoldoutsTime / n
      pushHoldoutsTimeMean = (stPushHoldoutsTimeMean $ zsStats state') * (n - 1) / n + pushHoldoutsTime / n
      resultUpdateTimeMean = (stResultUpdateTimeMean $ zsStats state') * (n - 1) / n + resultUpdateTime / n

      !stats'' = stats'
                 { stN = n
                 , stTurnaroundTimeMean = turnaroundTimeMean
                 , stResultReqTimeMean = resultReqTimeMean
                 , stHWUpdateTimeMean = hwUpdateTimeMean
                 , stModelApplicationTimeMean = modelApplicationTimeMean
                 , stPullHoldoutsTimeMean = pullHoldoutsTimeMean
                 , stPushHoldoutsTimeMean = pushHoldoutsTimeMean
                 , stResultUpdateTimeMean = resultUpdateTimeMean
                 }

      !state'' = state'
                 { zsStats = stats''
                 }

  -- putStrLn $ "Batch = " ++ show curBatch ++ " done processing"
  -- putStrLn $ "Stats: " ++ show (zsStats state')
               
  activeAttackLoop state'' ts benignPrefixMap

resultsLoop :: ZAPDOSState -> TofinoState -> Int -> IO ()
resultsLoop state ts numResults = do
  -- let maxResults = confMaxReportPrefixes (zsConfig state)
  
  resM <- readMaybeChan (zsResultsPipe state)
  case resM of
    Just (curTime, res) -> do
      printResult state curTime res
      -- when (numResults < maxResults) $ do
      --   () <- takeMVar (zsSelectTableLock state)
      --   (flagAsAttack ts (fst res))
      --   putMVar (zsSelectTableLock state) ()
      resultsLoop state ts (numResults + 1)
    Nothing -> do
      CC.threadDelay 1
      resultsLoop state ts numResults

  

printResult :: ZAPDOSState -> Double -> (Prefix, Features) -> IO ()
printResult state curTime res = do
  let conf = zsConfig state
      prefixesPerEpoch = confPrefixesPerEpoch conf
      bitsPerEpoch = confBitsPerEpoch conf
      zoomInThreshold = confZoomInThreshold conf
      epochDur = confEpochDuration conf
      benignProxThresh = confBenignProxThresh conf
      zeroMonitorsPerEpoch = 0
      nPrefixes = 1 -- V.length res
      nNonzeroPrefixes = 0 -- = res & V.filter (not . featuresIsZero . snd) & V.length
      printOne (Prefix k p, f) =
        [ show curTime
        , show (zsEpoch state)
        , ipv4_to_string k
        , show p
        , show zoomInThreshold
        , show bitsPerEpoch
        , show prefixesPerEpoch
        , show zeroMonitorsPerEpoch
        , show epochDur
        , show benignProxThresh
        , show (fZoomDecision f)
        ] ++ (featuresToVector p (round curTime) f & V.map show & V.toList)
  hPutStrLn (zsOutputFile state) $ L.intercalate "," $ printOne res
  hFlush (zsOutputFile state)

printMetadata :: ZAPDOSState -> Double -> IO ()
printMetadata state curTime = do
  hPutStrLn (zsMetadataFile state) $ L.intercalate "," $ statsToList state curTime (zsStats state)
  hFlush (zsMetadataFile state)

getInitialNextBatchTimes :: ZAPDOSState -> TimeSpec -> V.Vector TimeSpec
getInitialNextBatchTimes state cur =
  let conf = zsConfig state
      batchDur = fromNanoSecs (round (1000000000.0 * confEpochDuration conf / fromIntegral (confBatchesPerEpoch conf)))
      makeOne idx = cur + batchDur * fromIntegral idx
  in V.generate (confBatchesPerEpoch conf) makeOne
  

runZapdos :: ZAPDOSState -> IO ()
runZapdos state = do
  let conf = zsConfig state
  ts <- getTofinoState

  putStrLn $ "configuration: " ++ show conf

  clearAll ts
  writeStaticDefaults conf ts

  putStrLn "Pre-attack mode, gathering benign prefix map"

  !pm <- getBenignPrefixMap conf ts (confDurTillAttack conf)

  attackStartTime <- getTime Monotonic
  let state' = state
               { zsAttackStartTime = attackStartTime
               , zsNextBatchTimes = getInitialNextBatchTimes state attackStartTime
               }
  putStrLn "Active-attack mode..."

  -- Note: make sure each thread uses different client id when talking with switch_d
  lookbackThread <- CC.forkIO $ lookbackLoop state' (tsIncrClientId ts)
  resultsThread <- CC.forkIO $ resultsLoop state' (tsIncrClientId $ tsIncrClientId ts) 0

  activeAttackLoop state' ts pm


  
usage = "<random-forest model file>"
  ++ " <output file>"
  ++ " <metadata output file>"
  ++ " <zoom-in threshold>"
  ++ " <epoch duration (float seconds)>"
  ++ " <duration till attack (integer seconds)>"
  ++ " <benign prox threshold>"
  ++ " <update batch size>"

parseArgs :: [String] -> ZAPDOSState -> Maybe ZAPDOSState
parseArgs [ modelFile
          , outputFile
          , metadataFile
          , zoomInThresh
          , epochDur
          , durTillAttack
          , benignProxThresh
          , batchSize
          ] st =
  let conf = defaultZapdosConfig
             { confZoomInThreshold = read zoomInThresh
             , confEpochDuration = read epochDur
             , confDurTillAttack = read durTillAttack
             , confBenignProxThresh = read benignProxThresh
             , confBatchSize = read batchSize
             , confBatchesPerEpoch = confPrefixesPerEpoch defaultZapdosConfig `div` read batchSize
             }
      monitoredPrefixes =
        V.fromList [ fmap (,defaultInactivePrefix) [i..j-1]
                   | i <- [0, (confBatchSize conf) .. (confPrefixesPerEpoch conf - 1)]
                   , j <- [min (i + confBatchSize conf) (confPrefixesPerEpoch conf)]
                   ]
  in Just $ st
     { zsModelFilepath = modelFile
     , zsOutputFilepath = outputFile
     , zsMetadataFilepath = metadataFile
     , zsConfig = conf
     , zsMonitoredPrefixes = monitoredPrefixes
     , zsNonEmptyChildren = initPrefixes conf
     }
parseArgs _ _ = Nothing

loadModel :: ZAPDOSState -> IO ZAPDOSState
loadModel state = do
  putStrLn "Loading model..."
  !model <- RF.readModelFile $ zsModelFilepath state
  putStrLn "...loaded model."
  return $ state { zsModel = model }

openOutputFiles :: ZAPDOSState -> IO ZAPDOSState
openOutputFiles state = do
  outfile <- openFile (zsOutputFilepath state) WriteMode
  metadatafile <- openFile (zsMetadataFilepath state) WriteMode
  
  hPutStrLn metadatafile statsHeader
  
  return $ state
    { zsOutputFile = outfile
    , zsMetadataFile = metadatafile
    }
  
main :: IO ()
main = do
  args <- getArgs
  initState <- getZapdosState
  case parseArgs args initState of
    Just state -> loadModel state >>= openOutputFiles >>= runZapdos
    Nothing -> putStrLn usage

