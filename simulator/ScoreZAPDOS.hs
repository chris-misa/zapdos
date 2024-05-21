{-
 - Score the outputs of the ZAPDOS simulator
 -
 - Author: Chris Misa
 - Date: 2024-05-21
 -
 - See ../LICENSE
 -}

{-# LANGUAGE OverloadedStrings, DeriveGeneric, BangPatterns #-}


module Main (main) where

import Data.Function ((&))
import System.Environment
import Data.Word
import Data.Bits
import Data.Maybe
import qualified Data.List as L

import qualified Data.HashSet as HS
import qualified Control.Monad as CM
import qualified Control.Monad.Loops as ML

import GHC.Generics hiding (MetaData)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Vector as V
import Data.Csv -- from cassava

import qualified Packets as P

usage :: String
usage = "Usage: <trace file> <attack source list> <benign source data (format from TraceAnalysis.hs:distinctSourcesInfo)> <mrt output> <duration till attack> <total duration> <epoch duration>\n"
  ++ "Make sure to use mrt output from a single run (e.g., the mrt_*_NKprefixes files instead of the mrt_*_attackers files which have all prefixesPerEpoch results combined...\n"

{- This PrefixTree stuff should really be in it's own file to avoid duplication with MRT_RF* modules... -}

data PrefixTree = EmptyTree
                | Node !Int !Word32 PrefixTree PrefixTree -- Node j k left right
                -- where j is the prefix length and k is the prefix

prefixTreeBuild :: PrefixTree -> (Word32, Int) -> PrefixTree
prefixTreeBuild EmptyTree (k, j) = Node j k EmptyTree EmptyTree
prefixTreeBuild oldNode@(Node j k l r) new@(k', j') =
  let d = firstDiffBit k k'
      isDisjoint = j == j' || (d <= j && d <= j') -- Note that all prefixes in mrt should be disjoint
      newIsSubnet = not isDisjoint && j < j'
      newIsSupnet = not isDisjoint && j' < j
  in if isDisjoint
     then let d' = d - 1 in
          if k < k'
          then Node d' (preserveUpperBits k d') oldNode (Node j' k' EmptyTree EmptyTree)
          else Node d' (preserveUpperBits k d') (Node j' k' EmptyTree EmptyTree) oldNode
     else
     if newIsSubnet
     then if (k' `shiftR` (32 - (j + 1))) .&. 1 == 0
          then Node j k (prefixTreeBuild l new) r
          else Node j k l (prefixTreeBuild r new)
     else
     if newIsSupnet
     then if k < k'
          then Node j' k' oldNode EmptyTree
          else Node j' k' EmptyTree oldNode
     else
     error "We missed a case in buildTree!"
  where firstDiffBit :: Word32 -> Word32 -> Int
        firstDiffBit w1 w2 =
          rec w1 w2 1
          where rec _ _ 33 = 33
                rec w1 w2 n =
                      if 0x80000000 .&. w1 == 0x80000000 .&. w2
                      then rec (w1 `shiftL` 1) (w2 `shiftL` 1) (n + 1)
                      else n

        preserveUpperBits :: Word32 -> Int -> Word32
        preserveUpperBits w n = (w `shiftR` (32 - n)) `shiftL` (32 - n)

prefixTreeLookup :: PrefixTree -> Word32 -> Maybe (Word32, Int)
prefixTreeLookup (Node j k EmptyTree EmptyTree) k' =
    if k .&. P.maskForBits j == k' .&. P.maskForBits j
    then Just (k, j)
    else Nothing
prefixTreeLookup (Node j k l r) k' =
    if k .&. P.maskForBits j == k' .&. P.maskForBits j
    then if (k' `shiftR` (32 - (j + 1))) .&. 1 == 0
         then prefixTreeLookup l k'
         else prefixTreeLookup r k'
    else Nothing
prefixTreeLookup EmptyTree _ = Nothing





loadAttackSources :: String -> IO (HS.HashSet Word32)
loadAttackSources filename = do
  file <- readFile filename
  return $ file
    & lines
    & fmap P.string_to_ipv4
    & HS.fromList

data SourceInfo = SourceInfo {
        siFirstTime :: !Double,
        siSrc :: !String,
        siProto :: !Int,
        siUDPsport :: !Int
    } deriving (Generic, Show)
instance FromRecord SourceInfo

loadBenignSources :: Double -> Double -> String -> IO (Maybe (HS.HashSet Word32))
loadBenignSources attackStart totalDuration filepath = do
    file <- BL.readFile filepath
    case decode NoHeader file of
        Left err -> do
            putStrLn err
            return Nothing
        Right v -> do
            let timeZero = v & V.map siFirstTime & V.minimum -- benign source files are not in time order!!!
                startTime = timeZero + attackStart
                endTime = timeZero + totalDuration
                res = v
                    & V.filter ((>= startTime) . siFirstTime)
                    & V.filter ((<= endTime) . siFirstTime)
                    & fmap (P.string_to_ipv4 . siSrc)
                    & V.toList
                    & HS.fromList
            return (Just res)

data ASSUREDResultEntry = ASSUREDResultEntry {
    areTime :: !Double,
    areSrc :: !String,
    arePrefixLength :: !Int,
    areZoomInThresh :: String,
    areBitsPerEpoch :: String,
    arePrefixesPerEpoch :: String,
    areZeroMonitorsPerEpoch :: String,
    areEpochDur :: Double,
    areBenignProxThresh :: String,
    areDecision :: String,
    arePrefixLength2 :: String,
    areBytesFrom :: String,
    areBytesTo :: String,
    areRespReqDiff :: String,
    areLastActiveDiff :: String,
    areMinIPG :: String,
    areMaxIPG :: String,
    areAveIPG :: String,
    arePktsFrom :: String,
    arePktsTo :: String,
    areMinLen :: String,
    areMaxLen :: String,
    areAveLen :: String,
    areNSrcDstMonitors :: Int,
    areNActivePrefixes :: Int,
    areNZeroMonitors :: Int,
    areNHoldouts :: Int,
    areNZoomedInOn :: Int,
    areNCollisions :: Int,
    areNZeroToNonZero :: Int
  } deriving (Generic, Show)
instance FromRecord ASSUREDResultEntry

data MetaData = MetaData
  { mdNSrcDstMonitors :: !Int
  , mdNActivePrefixes :: !Int
  , mdNZeroMonitors :: !Int
  , mdNHoldouts :: !Int
  , mdNZoomedInOn :: !Int
  , mdNCollisions :: !Int
  , mdNZeroToNonZero :: !Int
  } deriving (Show)

zeroMetaData = MetaData
  { mdNSrcDstMonitors = 0
  , mdNActivePrefixes = 0
  , mdNZeroMonitors = 0
  , mdNHoldouts = 0
  , mdNZoomedInOn = 0
  , mdNCollisions = 0
  , mdNZeroToNonZero = 0
  }

loadASSUREDResults :: String -> IO (Maybe (V.Vector (Double, (Word32, Int), MetaData)))
loadASSUREDResults filepath = do
  file <- BL.readFile filepath
  case decode NoHeader file of
    Left err -> do
      putStrLn $ "CSV parse error: " ++ err
      return Nothing
    Right v -> do
      return $ Just $ V.map projectEntry v
  where projectEntry :: ASSUREDResultEntry -> (Double, (Word32, Int), MetaData)
        projectEntry r =
          let md = MetaData
                  { mdNSrcDstMonitors = areNSrcDstMonitors r
                  , mdNActivePrefixes = areNActivePrefixes r
                  , mdNZeroMonitors = areNZeroMonitors r
                  , mdNHoldouts = areNHoldouts r
                  , mdNZoomedInOn = areNZoomedInOn r
                  , mdNCollisions = areNCollisions r
                  , mdNZeroToNonZero = areNZeroToNonZero r
                  }
          in (areTime r, ((P.string_to_ipv4 . areSrc) r, arePrefixLength r), md)

data Stats = Stats {
    statsPkts :: !Int,
    statsBytes :: !Int,
    statsBenignPkts :: !Int,
    statsBenignBytes :: !Int,
    statsAttackPkts :: !Int,
    statsAttackBytes :: !Int,
    statsTPPkts :: !Int,
    statsTPBytes :: !Int,
    statsFPPkts :: !Int,
    statsFPBytes :: !Int,
    statsMetaData :: !MetaData
  } deriving (Show)

initStats :: Stats
initStats = Stats
  { statsPkts = 0
  , statsBytes = 0
  , statsBenignPkts = 0
  , statsBenignBytes = 0
  , statsAttackPkts = 0
  , statsAttackBytes = 0
  , statsTPPkts = 0
  , statsTPBytes = 0
  , statsFPPkts = 0
  , statsFPBytes = 0
  , statsMetaData = zeroMetaData
  }

incrStats :: Stats -> Int -> Bool -> Bool -> Bool -> Stats
incrStats !s len isBenign isAttack isDetected =
  let tp = if isAttack && isDetected then 1 else 0
      fp = if isBenign && isDetected then 1 else 0
      benignIncr = if isBenign then 1 else 0
      attackIncr = if isAttack then 1 else 0
  in s { statsPkts = statsPkts s + 1,
         statsBytes = statsBytes s + len,
         statsBenignPkts = statsBenignPkts s + benignIncr,
         statsBenignBytes = statsBenignBytes s + benignIncr * len,
         statsAttackPkts = statsAttackPkts s + attackIncr,
         statsAttackBytes = statsAttackBytes s + attackIncr * len,
         statsTPPkts = statsTPPkts s + tp,
         statsTPBytes = statsTPBytes s + tp * len,
         statsFPPkts = statsFPPkts s + fp,
         statsFPBytes = statsFPBytes s + fp * len
       }

putStatsHeader :: IO ()
putStatsHeader =
  putStrLn "time,pkts,bytes,benignPkts,benignBytes,attackPkts,attackBytes,tpPkts,tpBytes,fpPkts,fpBytes,nSrcDstMonitors,nActivePrefixes,nZeroMonitors,nHoldouts,nZoomedInOn,nCollisions,nZeroToNonZero"

putStats :: Double -> Stats -> IO ()
putStats curTime stats =
  [ show $ curTime
  , show $ statsPkts stats
  , show $ statsBytes stats
  , show $ statsBenignPkts stats
  , show $ statsBenignBytes stats
  , show $ statsAttackPkts stats
  , show $ statsAttackBytes stats
  , show $ statsTPPkts stats
  , show $ statsTPBytes stats
  , show $ statsFPPkts stats
  , show $ statsFPBytes stats
  , show $ mdNSrcDstMonitors (statsMetaData stats)
  , show $ mdNActivePrefixes (statsMetaData stats)
  , show $ mdNZeroMonitors (statsMetaData stats)
  , show $ mdNHoldouts (statsMetaData stats)
  , show $ mdNZoomedInOn (statsMetaData stats)
  , show $ mdNCollisions (statsMetaData stats)
  , show $ mdNZeroToNonZero (statsMetaData stats)
  ] & L.intercalate ","
    & putStrLn

-- State attackSrcs benignSrcs remainingRes curRes stats nextEpoch
--   remainingRes is a vector of results remaining to be added to the current attack list
--   curRes is the current state of which prefixes the system is detecting as part of the attack
data State = State
  { sAttackSrcs :: !(HS.HashSet Word32)
  , sBenignSrcs :: !(HS.HashSet Word32)
  , sRemainingRes :: !(V.Vector (Double, (Word32, Int), MetaData))
  , sCurRes :: !PrefixTree
  , sStats :: !Stats
  , sNextEpoch :: !Double
  , sEpochDur :: !Double
  }

procOne :: IO (Maybe P.Packet) -> State -> IO State
procOne nextPkt state = do
  nextPkt >>= updateState state
  where updateState :: State -> Maybe P.Packet -> IO State
        updateState !state !(Just p) = do
          let !curTime = P.timeS p
              (remainingRes', curRes', md) = updateResults curTime (sRemainingRes state) (sCurRes state)

          (nextEpoch', stats') <- updateEpoch (sEpochDur state) curTime (sNextEpoch state) (sStats state) md
              
          let src = P.ipv4_src p
              isBenign = src `HS.member` sBenignSrcs state
              isAttack = src `HS.member` sAttackSrcs state -- && not isBenign -- shouldn't matter now that things are actually disjoint...
              isDetected = prefixTreeLookup curRes' src & isJust
              
              !stats'' = incrStats stats' ((fromIntegral . P.ipv4_len) p) isBenign isAttack isDetected
              state' = state
                { sRemainingRes = remainingRes'
                , sCurRes = curRes'
                , sStats = stats''
                , sNextEpoch = nextEpoch'
                }
          procOne nextPkt state'
        updateState state Nothing = return state

        updateResults :: Double -> V.Vector (Double, (Word32, Int), MetaData) -> PrefixTree -> (V.Vector (Double, (Word32, Int), MetaData), PrefixTree, MetaData)
        updateResults curTime remaining cur
          | not (V.null remaining) && (\(x, _, _) -> x) (remaining V.! 0) <= curTime =
              let Just ((_, newPrefix, _), remaining') = V.uncons remaining
                  cur' = prefixTreeBuild cur newPrefix
              in updateResults curTime remaining' cur'
          | otherwise =
              let (_, _, md) = if not (V.null remaining) then remaining V.! 0 else (undefined, undefined, zeroMetaData)
              in (remaining, cur, md)

        updateEpoch :: Double -> Double -> Double -> Stats -> MetaData -> IO (Double, Stats)
        updateEpoch epochDuration curTime nextEpoch stats md =
          if nextEpoch == 0
          then return (curTime + epochDuration, stats { statsMetaData = md })
          else if nextEpoch <= curTime
          then do
            putStats curTime stats
            let inc t = if t <= curTime then inc (t + epochDuration) else t
            return (inc nextEpoch, initStats { statsMetaData = md })
          else return (nextEpoch, stats)

processPcapFile :: State -> String -> IO State
processPcapFile state filepath = do
  nextPkt <- P.readPcapFile filepath
  procOne nextPkt state

main :: IO ()
main = do
    args <- getArgs
    case args of
      [traceFile, attackFile, benignFile, mrtFile, durTillAttack, totalDuration, epochDuration] -> do
        
        !attackSrcs <- loadAttackSources attackFile
        -- putStrLn "Loaded attack source file"
        
        !benignSrcs <- loadBenignSources (read durTillAttack) (read totalDuration) benignFile
          >>= \a -> case a of
                      Just bs -> return bs
                      Nothing -> error $ "Failed to load benign sources file: " ++ benignFile
        -- putStrLn "Loaded benign source file"
        
        -- let intLen = HS.size (HS.intersection attackSrcs benignSrcs)
        -- putStrLn $ "  intersection between attack and benign has " ++ show intLen ++ " sources"
        !mrtRes <- loadASSUREDResults mrtFile
          >>= \a -> case a of
                      Just res -> return res
                      Nothing -> error $ "Failed to load ASSURED results file: " ++ mrtFile
        -- putStrLn "Loaded ASSURED results file"
        
        let initState = State
              { sAttackSrcs = attackSrcs
              , sBenignSrcs =  benignSrcs
              , sRemainingRes = mrtRes
              , sCurRes = EmptyTree
              , sStats = initStats
              , sNextEpoch = 0
              , sEpochDur = read epochDuration
              }

        putStatsHeader
        
        State { sStats = finalStats, sNextEpoch = finalEpoch } <- processPcapFile initState traceFile

        putStats finalEpoch finalStats
        
      _ -> putStrLn usage
        
        
