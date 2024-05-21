{-
 - Produce a list of uniform random IP addresses
 -
 - Author: Chris Misa
 - Date: 2024-05-21
 -
 - See ../LICENSE for conditions.
 -}

module UniformSources (main) where

import Data.Function ((&))
import System.Environment
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Get (runGet, getWord64le)
import Data.List (unfoldr)

import System.Random.Mersenne.Pure64 (pureMT, PureMT)
-- import Data.RVar (pureRVar)
import Data.Random (StdUniform(..), RVar, samplePure)

import qualified Packets as P

usage = "<number of sources to generate>"

main :: IO ()
main =  do
  args <- getArgs
  case args of
    [nsrcs] -> do
      seed <- B.readFile "/dev/urandom"
              >>= return . runGet getWord64le
      run (read nsrcs) seed
    _ -> putStrLn usage

run :: Int -> Word64 -> IO ()
run n seed =
  unfoldr makeOne (pureMT seed)
    & take n
    & fmap printOne
    & sequence
    >> return ()

  where makeOne :: PureMT -> Maybe (Word32, PureMT)
        makeOne gen = Just $ samplePure StdUniform gen

        printOne :: Word32 -> IO ()
        printOne x = putStrLn $ P.ipv4_to_string x
    
