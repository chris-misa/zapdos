{-
 - ZAPDOS simulator
 -
 - Author: Chris Misa
 - Date: 2024-05-21
 -
 - See ../LICENSE for conditions.
 -}

{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}

module ZAPDOS (main) where

import System.IO (hPutStrLn, stderr)
import Data.Function ((&))
import System.Environment
import Data.Word
import Data.Bits
import Data.Maybe
import Control.Monad (join)
import Control.Arrow ((***), first)
import qualified Data.List as L
import qualified Data.Set as St
import qualified Data.Vector as V
import qualified Data.HashMap.Strict as M

import System.Random.Mersenne.Pure64 (pureMT, PureMT)
import Immutable.Shuffle (shuffle)
import Data.RVar (pureRVar)

import GHC.Generics (Generic)
import Data.Vector.Strategies (NFData, parVector, using)

import qualified Control.Monad.Loops as ML

{- Local modules -}
import qualified Packets as P
import qualified RandomForest as RF
import qualified MatchActionTable as MT
import qualified BloomFilter as BF

import MatchActionTable (MAT, Prefix(..))
import Common -- RespReqList

seed :: Word64
seed = 12345

usage = "<pcap filepath> <random-forest model file> <prefixes per epoch> <bits per epoch> <zoom-in threshold> <epoch duration> <duration till attack> <benign prox threshold> <number of zero monitors per epoch>\n"
        ++ "defaults used in experiments:\n"
        ++ "  prefixes per epoch = 1500,\n"
        ++ "  bits per epoch = 4,\n"
        ++ "  zoom-in threshold = 0.5 (is w.r.t. probabilities emitted from model)\n"
        ++ "  epoch duration = 1 (in seconds)\n"
        ++ "  duration till attack = 120 (in seconds, depends on trace file used)\n"
        ++ "  benign prox threshold = 0\n"
        ++ "  number of zero monitors per epoch = 10000\n"
        ++ "note: \"duration till attack\" is used to catch distribution of benign prefixes before attack traffic starts (in seconds)"


data ASSUREDConfig = ASSUREDConfig
  { confFilepath :: String
  , confModelFilepath :: String
  , confPrefixesPerEpoch :: Int
  , confBitsPerEpoch :: Int
  , confZoomInThreshold :: Double
  , confModel :: RF.RandomForest
  , confEpochDuration :: Double -- in seconds
  , confDurTillAttack :: Double -- in seconds
  , confBenignProxThresh :: Double
  , confZeroMonitorsPerEpoch :: Int
  }

parseArgs :: [String] -> Maybe ASSUREDConfig
parseArgs [ filepath
          , modelFile
          , prefixesPerEpoch
          , bitsPerEpoch
          , zoomInThresh
          , epochDur
          , durTillAttack
          , benignProxThresh
          , zeroMonitorsPerEpoch ] =
  Just $ ASSUREDConfig
          { confFilepath = filepath
          , confModelFilepath = modelFile
          , confPrefixesPerEpoch = read prefixesPerEpoch
          , confBitsPerEpoch = read bitsPerEpoch
          , confZoomInThreshold = read zoomInThresh
          , confModel = undefined
          , confEpochDuration = read epochDur
          , confDurTillAttack = read durTillAttack
          , confBenignProxThresh = read benignProxThresh
          , confZeroMonitorsPerEpoch = read zeroMonitorsPerEpoch
          }
parseArgs _ = Nothing

loadModel :: ASSUREDConfig -> IO ASSUREDConfig
loadModel conf = do
  model <- RF.readModelFile $ confModelFilepath conf
  return $ conf { confModel = model }

main :: IO ()
main = do
  args <- getArgs
  case parseArgs args of
    Just conf -> loadModel conf >>= processPcapFile
    Nothing -> putStrLn usage

data Features = Features
  { fPktsFrom :: !Int
  , fPktsTo :: !Int
  , fBytesFrom :: !Int
  , fBytesTo :: !Int
  , fLastActiveEpoch :: !Double
  , fPrevTime :: !Double
  , fMinIPG :: !Double
  , fMaxIPG :: !Double
  , fAveIPG :: !Double
  , fMinLen :: !Double
  , fMaxLen :: !Double
  , fAveLen :: !Double
  , fRespReqList :: !RespReqList
  , fZoomDecision :: !Bool
  , fReportDecision :: !Bool
  , fScore :: !Double
  , fChildBitmap :: !Word32
  , fActiveChild :: !Bool
  } deriving (Generic)

instance NFData Features

zeroFeatures :: Features
zeroFeatures = Features
  { fPktsFrom = 0
  , fPktsTo = 0
  , fBytesFrom = 0
  , fBytesTo = 0
  , fLastActiveEpoch = 0
  , fPrevTime = 0
  , fMinIPG = 10000
  , fMaxIPG = 0
  , fAveIPG = 0
  , fMinLen = 10000
  , fMaxLen = 0
  , fAveLen = 0
  , fRespReqList = zeroRespReqList
  , fZoomDecision = False
  , fReportDecision = False
  , fScore = 0
  , fChildBitmap = 0
  , fActiveChild = False
  }

featuresIsZero :: Features -> Bool
featuresIsZero f = fPktsFrom f == 0 && fPktsTo f == 0

-- 
-- Reset features for accumulation in next epoch
-- Note that this is where we update lastActiveEpoch
--
resetFeatures :: Double -> (Prefix, Features) -> (Prefix, Features)
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

--
-- Converts features to a flat vector for the model
--
featuresToVector :: Int -> Double -> Features -> V.Vector Double
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
      , lastActiveDiff
      , minIPG
      , maxIPG
      , aveIPG
      , fromIntegral pktsFrom
      , fromIntegral pktsTo
      , minLen
      , maxLen
      , aveLen
      ]

data MetaData = MetaData
  { mSrc :: !Word32
  , mDst :: !Word32
  , mTime :: !Double
  , mLen :: !Int
  , mResps :: !RespReqList
  , mReqs :: !RespReqList
  , mReported :: !Bool
  , mMatched :: !Bool
  }

type BenignPrefixMap = M.HashMap (Word32, Int) Int

data Stats = Stats
  { stNSrcDstMonitors :: !Int
  , stNActivePrefixes :: !Int
  , stNZeroMonitors :: !Int
  , stNHoldouts :: !Int
  , stNZoomedInOn :: !Int
  , stNCollisions :: !Int
  , stNZeroToNonZero :: !Int
  }

zeroStats :: Stats
zeroStats = Stats
  { stNSrcDstMonitors = 0
  , stNActivePrefixes = 0
  , stNZeroMonitors = 0
  , stNHoldouts = 0
  , stNZoomedInOn = 0
  , stNCollisions = 0
  , stNZeroToNonZero = 0
  }

statsToList :: Stats -> [String]
statsToList s = fmap show
  [ stNSrcDstMonitors s
  , stNActivePrefixes s
  , stNZeroMonitors s
  , stNHoldouts s
  , stNZoomedInOn s
  , stNCollisions s
  , stNZeroToNonZero s
  ]

data State = State
  { sEpochEnd :: !Double
  , sReported :: !(MAT () MetaData)
  , sSrcMonitor :: !(MAT Features MetaData)
  , sDstMonitor :: !(MAT Features MetaData)
  , sZeroMonitor :: !(MAT (V.Vector BF.BloomFilter) MetaData)
  , sHoldouts :: !(V.Vector (Prefix, Features))
  , sRndState :: PureMT
  , sAttackStarted :: !Bool
  , sBenignPrefixes :: !BenignPrefixMap
  , sStats :: !Stats
  }

computeIPGStats :: Double -> Double -> Double -> Double -> Double -> (Double, Double, Double)
computeIPGStats time prevTime minIPG maxIPG aveIPG
    | prevTime == 0 = (1000.0, 0.0, 0.0)
    | otherwise =
        let ipg = time - prevTime
            minIPG' = min ipg minIPG
            maxIPG' = max ipg maxIPG
            aveIPG' = 0.5 * ipg + 0.5 * aveIPG --- TODO: add alpha as param!
        in (minIPG', maxIPG', aveIPG')

computeLenStats :: Double -> Double -> Double -> Double -> (Double, Double, Double)
computeLenStats len minLen maxLen aveLen =
    let minLen' = min len minLen
        maxLen' = max len maxLen
        aveLen' = 0.5 * len + 0.5 * aveLen --- TODO: add alpha as param!
    in (minLen', maxLen', aveLen')

--
-- Look up the given prefix and return its benign proximity score
--
getBenignProx :: BenignPrefixMap -> (Word32, Int) -> Double
getBenignProx pm (k, p) =
    case M.lookup (k, p) pm of
        Just n -> fromIntegral n / fromIntegral (2 ^ (32 - p))
        Nothing -> 0.0

initZeroMonitor :: ASSUREDConfig -> MAT (V.Vector BF.BloomFilter) MetaData
initZeroMonitor conf = MT.build key update initTable
  where nbfs = (32 `div` confBitsPerEpoch conf) + 1
        initBloomFilters =  V.generate nbfs (\i -> BF.empty (12345 * fromIntegral i) 100000 4)
        initTable = V.singleton (Prefix 0 0, initBloomFilters)
        key = const 0
        update _ md bfs
          | mMatched md = (md, bfs)
          | otherwise =
              let updateOne i bf =
                    let key = mSrc md .&. P.maskForBits (i * confBitsPerEpoch conf)
                    in BF.insert key bf
                  bfs' = V.imap updateOne bfs
              in (md, bfs')

initSrcMonitor :: ASSUREDConfig -> MAT Features MetaData
initSrcMonitor conf = MT.build key update initPrefixes
  where key = mSrc
        update (Prefix k p) md f =
          let !(!minIPG, !maxIPG, !aveIPG) =
                computeIPGStats (mTime md) (fPrevTime f) (fMinIPG f) (fMaxIPG f) (fAveIPG f)
              !(!minLen, !maxLen, !aveLen) =
                computeLenStats (fromIntegral $ mLen md) (fMinLen f) (fMaxLen f) (fAveLen f)
              -- childIdx is the bits between p and p + bitsPerEpoch of the current source
              !childIdx =
                if p + confBitsPerEpoch conf < 32
                then (mSrc md .&. complement (P.maskForBits p)) `shiftR` (32 - (p + confBitsPerEpoch conf))
                else 0
              !f' = f
                 { fPrevTime = mTime md
                 , fPktsFrom = fPktsFrom f + 1
                 , fBytesFrom = fBytesFrom f + mLen md
                 , fMinIPG = minIPG
                 , fMaxIPG = maxIPG
                 , fAveIPG = aveIPG
                 , fMinLen = minLen
                 , fMaxLen = maxLen
                 , fAveLen = aveLen
                 , fRespReqList = applyRespReqIncr (fRespReqList f) (mResps md)
                 , fChildBitmap = fChildBitmap f .|. (1 `shiftL` fromIntegral childIdx)
                 }
          in (md { mMatched = True }, f')

initDstMonitor :: MAT Features MetaData
initDstMonitor = MT.build key update initPrefixes
  where key = mDst
        update pfx md f =
          let !f' = f
                 { fPktsTo = fPktsTo f + 1
                 , fBytesTo = fBytesTo f + mLen md
                 , fRespReqList = applyRespReqIncr (fRespReqList f) (mReqs md)
                 }
          in (md { mMatched = True }, f')

initPrefixes :: V.Vector (Prefix, Features)
-- initPrefixes = V.singleton (Prefix 0 0, zeroFeatures)
initPrefixes = V.generate (2 ^ initDepth) genOne
  where genOne :: Int -> (Prefix, Features)
        genOne i =
          let k = fromIntegral i `shiftL` (32 - initDepth)
          in (Prefix k initDepth, zeroFeatures)

        initDepth = 8

initState :: ASSUREDConfig -> State
initState conf =
  let 
  in State
  { sEpochEnd = 0
  , sReported = reported
  , sSrcMonitor = initSrcMonitor conf
  , sDstMonitor = initDstMonitor
  , sZeroMonitor = initZeroMonitor conf
  , sHoldouts = V.empty
  , sRndState = (pureMT seed)
  , sAttackStarted = False
  , sBenignPrefixes = M.empty
  , sStats = zeroStats
  }
  where reported :: MAT () MetaData
        reported = MT.build key update V.empty
          where key = mSrc
                update _ md _ = (md { mReported = True }, ())


processPcapFile :: ASSUREDConfig -> IO ()
processPcapFile conf = do
  pkts <- P.readPcapFile (confFilepath conf)
  processPacket conf pkts (initState conf)

processPacket :: ASSUREDConfig -> IO (Maybe P.Packet) -> State -> IO () 
processPacket conf pkts state = pkts >>= pp
  where pp :: Maybe P.Packet -> IO ()
        pp (Just p) = do
          !state' <-
            case sAttackStarted state of
              False -> preAttackMode conf state p 
              True -> attackMode conf state p
          processPacket conf pkts state'
        pp Nothing = return ()

preAttackMode :: ASSUREDConfig -> State -> P.Packet -> IO State
preAttackMode conf state p =
  let curTime = P.timeS p
      nextEpoch = sEpochEnd state
      nextEpoch' =
        if nextEpoch == 0
        then curTime + confDurTillAttack conf
        else nextEpoch
  in
    if curTime < nextEpoch'
    then return $ state
      { sEpochEnd = nextEpoch'
      , sBenignPrefixes = addToBenignPrefixMap (sBenignPrefixes state) (P.ipv4_src p)
      }
    else
      let state' = state
                 { sEpochEnd = nextEpoch'
                 , sBenignPrefixes = filloutBenignPrefixMap (sBenignPrefixes state)
                 , sAttackStarted = True
                 }
      in attackMode conf state' p
  where addToBenignPrefixMap :: BenignPrefixMap -> Word32 -> BenignPrefixMap
        addToBenignPrefixMap pm p = M.insert (p, 32) 1 pm

        filloutBenignPrefixMap :: BenignPrefixMap -> BenignPrefixMap
        filloutBenignPrefixMap pm = f pm 32
            where f pm i
                    | i >= 0 =
                        let correctLength ((_, p), _) = p == i
                            addToParent pm' ((k, p), n) =
                                M.alter add key pm'
                                where key = (preserveUpperBits k (p - 1), p - 1)
                                      add Nothing = Just n
                                      add (Just n') = Just (n + n')
                            pm' = M.toList pm
                                & filter correctLength
                                & foldl addToParent pm
                        in f pm' (i - 1)
                    | otherwise = pm

attackMode :: ASSUREDConfig -> State -> P.Packet -> IO State
attackMode conf state p = do
  let curTime = P.timeS p
      nextEpoch = sEpochEnd state
  if curTime >= nextEpoch
  then do
    -- hPutStrLn stderr "======== processing epoch update ============"
    let !(!state', !results) = attackModeComputeEpoch conf curTime state
    printResults conf results state'
    -- printDiagnostics conf state' -- uncomment to dump some non-results stuff per-epoch
    return $ attackModeOnePacket conf p state'
  else return $ attackModeOnePacket conf p state
      
attackModeOnePacket :: ASSUREDConfig -> P.Packet -> State -> State
attackModeOnePacket conf p state =
  let !(!resps, !reqs) = getRespReqIncr p

      -- Project packet into metadata
        
      !md = MetaData
          { mSrc = P.ipv4_src p
          , mDst = P.ipv4_dst p
          , mTime = P.timeS p
          , mLen = fromIntegral $ P.ipv4_len p
          , mResps = resps
          , mReqs = reqs
          , mReported = False
          , mMatched = False
          }

      -- Apply the pipeline

      !(!md1, !reported') = MT.apply md (sReported state) in 
  if mReported md1
  then state
  else
    let !(!md2, !srcMonitor') = MT.apply md1 (sSrcMonitor state)
        !(!md3, !dstMonitor') = MT.apply md2 (sDstMonitor state)
        !(_, !zeroMonitor') = MT.apply md3 (sZeroMonitor state)
    in state
      { sReported = reported'
      , sSrcMonitor = srcMonitor'
      , sDstMonitor = dstMonitor'
      , sZeroMonitor = zeroMonitor'
      }

judgePrefix ::
     ASSUREDConfig
  -> Double
  -> BenignPrefixMap
  -> (Prefix, Features)
  -> (Prefix, Features)
judgePrefix conf epoch benignPrefixes (Prefix k p, f)
  | fPktsFrom f == 0 || fMinIPG f == (-1.0) =
      let f' = f { fZoomDecision = False }
      in (Prefix k p, f')
  | otherwise = 
      let fVec = featuresToVector p epoch f
          resp = RF.predict fVec (confModel conf)
          zoomDecision = resp >= confZoomInThreshold conf
          reportDecision = zoomDecision &&
            (p >= 32 || getBenignProx benignPrefixes (k, p) <= confBenignProxThresh conf)
          f' = f
              { fZoomDecision = zoomDecision
              , fReportDecision = reportDecision
              , fScore = resp
              }
      in (Prefix k p, f')

zoomIn :: Int -> (Prefix, Features) -> V.Vector (Prefix, Features)
zoomIn n (Prefix k p, f) =
  V.generate (2 ^ n) genOne
  where genOne :: Int -> (Prefix, Features)
        genOne i =
          let k' = k .|. fromIntegral (i `shiftL` (32 - (p + n)))
              activeChild = fChildBitmap f .&. (1 `shiftL` i) /= 0
          in (Prefix k' (p + n), f { fActiveChild = activeChild })

mergeSrcDst :: (Prefix, Features) -> (Prefix, Features) -> (Prefix, Features)
mergeSrcDst (Prefix k j, srcF) (Prefix k' j', dstF)
  | k == k' && j == j' =
    let f = srcF
          { fPktsTo = fPktsTo dstF
          , fBytesTo = fBytesTo dstF
          , fRespReqList = applyRespReqIncr (fRespReqList srcF) (fRespReqList dstF)
          }
    in (Prefix k j, f)
  | otherwise = error "Mis-matched prefixes in mergeSrcDst"


-- note that per-packet operations might not be worth parallelizing, but the bulk operations (e.g., applying the model) in computeEpoch might be...
attackModeComputeEpoch :: ASSUREDConfig -> Double -> State -> (State, V.Vector (Prefix, Features))
attackModeComputeEpoch conf curTime state =
  let nextEpoch = sEpochEnd state
      nextEpoch' =
        let step x = if curTime >= x then step (x + confEpochDuration conf) else x
        in step nextEpoch

      -- Extract results from match-action tables

      srcRes :: V.Vector (Prefix, Features)
      srcRes = MT.extract $ sSrcMonitor state

      dstRes :: V.Vector (Prefix, Features)
      dstRes = MT.extract $ sDstMonitor state

      zeroMonRes :: V.Vector (BF.BloomFilter)
      zeroMonRes = snd $ (MT.extract $ sZeroMonitor state) V.! 0

      -- Compute updated tables for next epoch

      judgements :: V.Vector (Prefix, Features)
      judgements = V.zipWith mergeSrcDst srcRes dstRes
                 & V.map (judgePrefix conf nextEpoch (sBenignPrefixes state))
                 & (`using` parVector (V.length srcRes `div` 16))

      -- apparently preserving the order matters a lot --- without it, we get stuck alot
      (newReports, preZoomIns) = V.partition (fReportDecision . snd) judgements

      ((zoomIns, emptyZoomIns), theRest) = preZoomIns
        & V.partition (fZoomDecision . snd)
        & join (***) (V.map (resetFeatures nextEpoch)) -- join (***) f == (\(x, y) -> (f x, f y))
        & first (V.concatMap (zoomIn (confBitsPerEpoch conf))) -- first f == (\(x, y) -> (f x, y)) -- zoomIn sets fActiveChild...
        & first (V.partition (fActiveChild . snd))
        & first (join (***) (V.map (\(p, f) -> (p, f { fChildBitmap = 0, fActiveChild = False })))) -- have to reset the child bitmap fields before next epoch...

      wasActive :: (Prefix, Features) -> (Bool, (Prefix, Features))
      wasActive (Prefix k p, f) =
        let a = BF.member k (zeroMonRes V.! (p `div` confBitsPerEpoch conf))
        in (a, (Prefix k p, zeroFeatures { fScore = fScore f }))

      (activeHoldouts, inactiveHoldouts) = sHoldouts state
        & V.map wasActive
        & (`using` parVector (V.length (sHoldouts state) `div` 16))
        & V.partition fst 
        & join (***) (V.map snd)

      (reserve, rndState') = shuffle (emptyZoomIns V.++ theRest V.++ inactiveHoldouts) (sRndState state)

      allRemaining = zoomIns V.++ activeHoldouts V.++ reserve

      -- Update match-action tables

      reported = MT.append (sReported state) (V.map (id *** const ()) (V.force newReports)) -- (id *** const ()) == \(pfx, _) -> (pfx, ())

      (pfxsToMonitor, holdouts) =
        V.splitAt (confPrefixesPerEpoch conf) allRemaining
        & join (***) V.force -- try forcing both of these to explicitly remove any refereces between epochs...

      srcMonitor = MT.update (sSrcMonitor state) pfxsToMonitor
      dstMonitor = MT.update (sDstMonitor state) pfxsToMonitor

      zeroMonitor = MT.update (sZeroMonitor state)
        $ V.singleton (Prefix 0 0, V.map BF.clear zeroMonRes)

      stats = Stats
        { stNSrcDstMonitors = V.length judgements
        , stNActivePrefixes = V.length (V.filter (featuresIsZero . snd) judgements)
        , stNZeroMonitors = 0
        , stNHoldouts = V.length $ sHoldouts state
        , stNZoomedInOn = V.length zoomIns `div` (2 ^ confBitsPerEpoch conf)
        , stNCollisions = 0
        , stNZeroToNonZero = V.length activeHoldouts
        }

      state' = state
        { sEpochEnd = nextEpoch'
        , sReported = reported
        , sSrcMonitor = srcMonitor 
        , sDstMonitor = dstMonitor
        , sZeroMonitor = zeroMonitor 
        , sHoldouts = holdouts
        , sRndState = rndState'
        , sStats = stats
        }
  in (state', newReports)

printResults :: ASSUREDConfig -> V.Vector (Prefix, Features) -> State -> IO ()
printResults conf res state =
  let epoch = sEpochEnd state
      prefixesPerEpoch = confPrefixesPerEpoch conf
      bitsPerEpoch = confBitsPerEpoch conf
      zoomInThreshold = confZoomInThreshold conf
      epochDur = confEpochDuration conf
      benignProxThresh = confBenignProxThresh conf
      zeroMonitorsPerEpoch = confZeroMonitorsPerEpoch conf
      nPrefixes = V.length res
      nNonzeroPrefixes = res & V.filter (not . featuresIsZero . snd) & V.length
      printOne (Prefix k p, f) =
        [ show epoch
        , P.ipv4_to_string k
        , show p
        , show zoomInThreshold
        , show bitsPerEpoch
        , show prefixesPerEpoch
        , show zeroMonitorsPerEpoch
        , show epochDur
        , show benignProxThresh
        , show (fZoomDecision f)
        ] ++ (featuresToVector p epoch f & V.map show & V.toList)
          ++ (statsToList $ sStats state)
  in res
      & V.filter (fReportDecision . snd)
      & V.mapM_ (putStrLn . L.intercalate "," . printOne)


printDiagnostics :: ASSUREDConfig -> State -> IO ()
printDiagnostics conf state = do
  hPutStrLn stderr
    $  "-------------------------------\n"
    ++ "      State diagnostics:\n"
    ++ "-------------------------------\n"
    ++ "  sEpochEnd = " ++ show (sEpochEnd state)
    ++ "  sReported length = " ++ show (V.length (MT.extract $ sReported state))
    ++ "  sSrcMonitor length = " ++ show (V.length (MT.extract $ sSrcMonitor state))
    ++ "  sDstMonitor length = " ++ show (V.length (MT.extract $ sDstMonitor state))
    ++ "  sZeroMonitor length = " ++ show (V.length (MT.extract $ sZeroMonitor state))
    ++ "  sHoldouts length = " ++ show (V.length $ sHoldouts state)
  -- putStrLn "  sSrcMonitor:"
  -- V.mapM_ printFeaturesDebug $ MT.extract $ sSrcMonitor state
  -- putStrLn "  sDstMonitor:"
  -- V.mapM_ printFeaturesDebug $ MT.extract $ sDstMonitor state
  -- putStrLn "  sReported:"
  -- V.mapM_ (\(pfx, ()) -> putStrLn (show pfx)) $ MT.extract $ sReported state

printFeaturesDebug :: (Prefix, Features) -> IO ()
printFeaturesDebug (Prefix k p, f) =
  hPutStrLn stderr . L.intercalate "," $
    [ P.ipv4_to_string k
    , show p
    , show $ fPktsFrom f
    , show $ fPktsTo f
    , show $ fBytesFrom f
    , show $ fBytesTo f
    , show $ fZoomDecision f
    , show $ fReportDecision f
    ]
