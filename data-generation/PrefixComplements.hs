{-
 - Generates sources from complent of
 - prefixes of given list of sources
 - at a particular prefix length.
 -
 - Author: Chris Misa
 - Date: 2024-05-21
 -
 - See ../LICENSE for conditions.
 -}

{-# LANGUAGE DeriveGeneric #-}

module PrefixComplements (main) where

import Data.Function ((&))
import System.Environment
import System.IO (stderr, hPutStrLn)
import Data.Word
import Data.Bits
import Data.Maybe
import qualified Data.List as L
import qualified Data.Set as St
import qualified Data.Vector as V

import qualified Data.HashMap.Strict as M -- from unordered-containers

import qualified Control.Monad.Loops as ML

import System.Random.Mersenne.Pure64 (pureMT, PureMT)
import Data.Random (stdUniform, shuffle)
import Data.RVar (pureRVar, RVar)

import Control.DeepSeq (force)
import Control.Parallel.Strategies (using, parList, parListChunk, rdeepseq, NFData)
import GHC.Generics (Generic)

import qualified Data.ByteString.Lazy as BL
import Data.Csv -- from cassava

import qualified Packets as P

seed = 12345

type PrefixKey = (Word32, Int)
type PrefixCounts = M.HashMap PrefixKey Int

expandPrefixesToRoot benignLength pm =
    L.foldl' fillInPrefixLength pm [benignLength-1,benignLength-2..0]
    where fillInPrefixLength pm prefixLength =
            let children = M.filterWithKey (\(_, l) _ -> l == prefixLength + 1) pm
                addParent pm' (addr, l) x = -- Note: l == prefixLength + 1
                    let sibling = getSibling (addr, l)
                        parent = ((addr .&. P.maskForBits prefixLength), prefixLength)
                    in case (M.lookup parent pm', M.lookup sibling children) of
                        (Just _, _) -> pm' -- already added a parent for this child (via it's sibling)
                        (Nothing, Just x') -> M.insert parent (x + x') pm'
                        (Nothing, Nothing) -> M.insert parent x pm'
                parents = M.foldlWithKey' addParent M.empty children
            in M.union parents pm

          getSibling (addr, l) =
            let addr' = (addr .&. P.maskForBits (l-1)) .|. (complement addr .&. (1 `shiftL` (32 - l)))
            in (addr', l)

data SourceInfo = SourceInfo {
        siFirstTime :: !Double,
        siSrc :: !String,
        siProto :: !Int,
        siUDPsport :: !Int
    } deriving (Generic, Show)
instance FromRecord SourceInfo

readBenignSrcs :: String -> Double -> Double -> IO PrefixCounts
readBenignSrcs filepath startTimeRel endTimeRel = do
    file <- BL.readFile filepath
    case decode NoHeader file of
        Left err -> do
            putStrLn err
            return M.empty
        Right v -> do
            let firstTime = siFirstTime (v V.! 0)
                startTime = firstTime + startTimeRel
                endTime = firstTime + endTimeRel
                res = v
                    & V.filter ((>= startTime) . siFirstTime)
                    & V.filter ((<= endTime) . siFirstTime)
                    & V.map (P.string_to_ipv4 . siSrc)
                    & V.foldl' buildMap M.empty
                    & expandPrefixesToRoot 32
            return res
    where buildMap pm src = M.insert (src, 32) 1 pm

--
-- Produces the complement of given prefixes at given prefix length
--
getPrefixComplements :: PrefixCounts -> Int -> [PrefixKey]
getPrefixComplements pm depth =
    M.keys pm
        & filter (\(_, d) -> d == depth - 1)
        & concatMap (\(k, d) -> let d' = d + 1 in [(k .|. (1 `shiftL` (32 - d')), d'), (k, d')])
        & filter (\k -> not (M.member k pm))

getSources :: [PrefixKey] -> Int -> [Word32]
getSources prefixes n =
    let (prefixesShuf, g) = pureRVar (shuffle prefixes) (pureMT seed)
    in L.unfoldr (\gen -> Just (pureRVar (stdUniform :: RVar Word32) gen)) g
            & take n
            & zip (cycle prefixesShuf)
            & fmap (\((k, d), r) -> k .|. (r .&. complement (P.maskForBits d)))
        
onePrefixLength :: PrefixCounts -> Int -> Int -> IO ()
onePrefixLength benignSrcs numSrcs prefixLength = do
    let complPrefixes = getPrefixComplements benignSrcs prefixLength
        srcs = getSources complPrefixes numSrcs
    hPutStrLn stderr ("Got " ++ (show $ length complPrefixes) ++ " prefixes of length " ++ (show prefixLength))
    if length complPrefixes > 0
    then do
        srcs
            & fmap (\s -> putStrLn $ (show prefixLength) ++ "," ++ P.ipv4_to_string s)
            & sequence
        return ()
    else return ()

usage :: String
usage = "USAGE: <benign source list file> <min time> <max time> <number of complement sources to generate> <prefix length 1> <prefix length 2> ... <prefix length n>"
        ++ "Note that <benign source list file> should be the output of TraceAnalysis.hs with distinctSourcesInfo query and min and max time are a range of times relative to beginning of this file to extract benign source addresses from"

main :: IO ()
main = do
    args <- getArgs
    case args of
        benignSourceFile : startTime : endTime : n : prefixLengths -> do
            benignSrcs <- readBenignSrcs benignSourceFile (read startTime) (read endTime)
            fmap (onePrefixLength benignSrcs (read n)) (fmap read prefixLengths) & sequence
            return ()
        _ -> putStrLn usage


