{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}

module Common where

import Data.Bits
import Data.Word
import Data.Function ((&))
import Data.Hashable
import GHC.Generics hiding (Prefix)
import qualified Data.List as L
import qualified Data.HashMap.Strict as M

import Control.Concurrent.MVar
import Control.Concurrent.Chan.Unagi.NoBlocking (newChan, tryReadChan, Element(..), writeChan, InChan, OutChan)
import Control.DeepSeq (NFData)

--
-- Common parameters of ZAPDOS algorithms
-- Note that some of these must be same in software and hardware
--
data ZAPDOSConfig = ZAPDOSConfig
  { confPrefixesPerEpoch :: Int
  , confBitsPerEpoch :: Int
  , confZoomInThreshold :: Double
  , confEpochDuration :: Double -- (in seconds)
  , confDurTillAttack :: Int -- how long to wait in pre-attack mode before active-attack mode (in seconds)
  , confBenignProxThresh :: Double
  , confLookbackBits :: Int -- size of lookback Bloom filter(s)
  , confInitDepth :: Int -- how long of prefix to start with initially
  
  , confBatchSize :: Int
  , confBatchesPerEpoch :: Int

  , confMaxReportPrefixes :: Int
  } deriving (Show)

defaultZapdosConfig :: ZAPDOSConfig
defaultZapdosConfig = ZAPDOSConfig
  { confPrefixesPerEpoch = 1500
  , confBitsPerEpoch = 4
  , confZoomInThreshold = 0.5
  , confEpochDuration = 1
  , confDurTillAttack = 120
  , confBenignProxThresh = 0.0
  , confLookbackBits = 2 ^ 10
  , confInitDepth = 8
  
  , confBatchSize = 100
  , confBatchesPerEpoch = 1500 `div` 100
  , confMaxReportPrefixes = 10000
  }

--
-- Common definition of a prefix
--
data Prefix = Prefix !Word32 !Int
  deriving (Eq, Generic, NFData)

instance Show Prefix where
  show (Prefix k j) = ipv4_to_string k ++ "/" ++ show j

instance Hashable Prefix where
  hash (Prefix p l) = hash (p, l)
--
-- For multi-protocol resp/req diff, we need to keep track of a vector of response and request counts
--
data RespReq = RespReq !Int !Int
  deriving (Show, Generic, NFData)

data RespReqList = RespReqList
  { rrListDNS :: !RespReq
  , rrListNTP :: !RespReq
  , rrListSSDP :: !RespReq
  , rrListTCP :: !RespReq
  } deriving (Show, Generic, NFData)

zeroRespReqList :: RespReqList
zeroRespReqList = RespReqList z z z z
  where z = RespReq 0 0

--
-- Per-prefix features
--
data Features = Features
  { fPktsFrom :: !Int
  , fPktsTo :: !Int
  , fBytesFrom :: !Int
  , fBytesTo :: !Int
  , fLastActiveEpoch :: !Int
  , fPrevTime :: !Double -- TODO: to we need this here?
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
  , fIsInactive :: !Bool
  } deriving (Show, Generic, NFData)

zeroFeatures :: Features
zeroFeatures = Features
  { fPktsFrom = 0
  , fPktsTo = 0
  , fBytesFrom = 0
  , fBytesTo = 0
  , fLastActiveEpoch = 0
  , fPrevTime = 0
  , fMinIPG = 0
  , fMaxIPG = 0
  , fAveIPG = 0
  , fMinLen = 0
  , fMaxLen = 0
  , fAveLen = 0
  , fRespReqList = zeroRespReqList
  , fZoomDecision = False
  , fReportDecision = False
  , fScore = 0
  , fChildBitmap = 0
  , fActiveChild = False
  , fIsInactive = False
  }

defaultInactivePrefix :: (Prefix, Features)
defaultInactivePrefix = (Prefix 0 (-1), zeroFeatures { fIsInactive = True } )

--
-- Prefix map used for benign-proximity metric's benign prefixs as well as CPU-side look-back maps
--
type PrefixMap = M.HashMap Prefix Int

--
-- Binary data utilities
--

maskForBits :: Int -> Word32
maskForBits n = (0xFFFFFFFF `shiftL` (32 - n)) .&. 0xFFFFFFFF

ipv4_to_string :: Word32 -> String
ipv4_to_string ip = L.intercalate "." . snd $ foldr (\x (i,o) -> (i, (show ((i `shiftR` x) .&. 0xFF)):o)) (ip,[]) [24,16..0]

string_to_ipv4 :: String -> Word32
string_to_ipv4 str =
    str
    & fmap (\c -> if c == '.' then '\n' else c)
    & lines
    & zip [24,16..0]
    & fmap (\(b, x) -> (read x `shiftL` b))
    & foldl1 (+)

-- 
-- Returns the 1-based index of the first differing bit from msb to lsb
-- or 33 if all 32 bits of both words are the same
--
firstDiffBit :: Word32 -> Word32 -> Int
firstDiffBit w1 w2 = rec w1 w2 1
    where rec _ _ 33 = 33
          rec w1 w2 n =
            if 0x80000000 .&. w1 == 0x80000000 .&. w2
            then rec (w1 `shiftL` 1) (w2 `shiftL` 1) (n + 1)
            else n

preserveUpperBits :: Word32 -> Int -> Word32
preserveUpperBits w n = (w `shiftR` (32 - n)) `shiftL` (32 - n)


--
-- RespReqList utilities
--
  
-- Really should be called "mergeRespReq" or "sumRespReq"...
applyRespReqIncr :: RespReqList -> RespReqList -> RespReqList
applyRespReqIncr l1 l2 = RespReqList
  { rrListDNS = respReqAdd (rrListDNS l1) (rrListDNS l2)
  , rrListNTP = respReqAdd (rrListNTP l1) (rrListNTP l2)
  , rrListSSDP = respReqAdd (rrListSSDP l1) (rrListSSDP l2)
  , rrListTCP = respReqAdd (rrListTCP l1) (rrListTCP l2)
  }
  where respReqAdd :: RespReq -> RespReq -> RespReq
        respReqAdd (RespReq res req) (RespReq res' req') = RespReq (res + res') (req + req')

computeRespReqDiff :: RespReqList -> Int
computeRespReqDiff l =
  [ rrListDNS l 
  , rrListNTP l 
  , rrListSSDP l 
  , rrListTCP l 
  ] & fmap respReqDiff
    & L.foldl' max 0
  where respReqDiff :: RespReq -> Int
        respReqDiff (RespReq res req) = res - req



--
-- Features utilities
--

featuresIsZero :: Features -> Bool
featuresIsZero f = fPktsFrom f == 0 && fPktsTo f == 0



--
-- PrefixMap utilities
--

--
-- Fill out a benign prefix map that has only /32 sources by aggregating at all prefix lengths
--
filloutPrefixMap :: PrefixMap -> PrefixMap
filloutPrefixMap pm = f pm 32
    where f pm i
            | i >= 0 =
                let correctLength (Prefix _ p, _) = p == i
                    addToParent pm' (Prefix k p, n) =
                        M.alter add key pm'
                        where key = Prefix (preserveUpperBits k (p - 1)) (p - 1)
                              add Nothing = Just n
                              add (Just n') = Just (n + n')
                    pm' = M.toList pm
                        & filter correctLength
                        & foldl addToParent pm
                in f pm' (i - 1)
            | otherwise = pm

--
-- Look up the given prefix and return its benign proximity score
--
getBenignProx :: PrefixMap -> Prefix -> Double
getBenignProx pm (Prefix k p) =
    case M.lookup (Prefix k p) pm of
        Just n -> fromIntegral n / fromIntegral (2 ^ (32 - p))
        Nothing -> 0.0




--
-- Wrapper to get chan to ignore reads when empty without missing elements...
--

data MaybeChan a = MaybeChan
  { mcInChan :: InChan a
  , mcOutChan :: OutChan a
  , mcOutElem :: MVar (Element a)
  }

newMaybeChan :: IO (MaybeChan a)
newMaybeChan = do
  (i, o) <- newChan
  e <- tryReadChan o
  eVar <- newMVar e
  return $ MaybeChan
    { mcInChan = i
    , mcOutChan = o
    , mcOutElem = eVar
    }

readMaybeChan :: MaybeChan a -> IO (Maybe a)
readMaybeChan c = do
  e <- takeMVar $ mcOutElem c
  outM <- tryRead e
  case outM of
    Just out -> do
      e' <- tryReadChan $ mcOutChan c
      putMVar (mcOutElem c) e'
      return $ Just out
    Nothing -> do
      putMVar (mcOutElem c) e
      return Nothing
  
writeMaybeChan :: MaybeChan a -> a -> IO ()
writeMaybeChan c x = writeChan (mcInChan c) x
  
