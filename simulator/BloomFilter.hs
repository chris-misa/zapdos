{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE TupleSections #-}

module BloomFilter (
        BloomFilter,
        empty,
        insert,
        member,
        clear
    ) where


import System.Random.Mersenne.Pure64 (pureMT)
import Data.Random
import Control.Monad.State
import Data.Word
import Data.Function ((&))

import qualified Data.Vector.Unboxed as V
import qualified Data.Bit as B
import qualified Data.List as L

-- BloomFilter m k hashes data
data BloomFilter = BloomFilter
  { bfM :: !Int
  , bfK :: !Int
  , bfHashes :: ![(Word32, Word32)]
  , bfData :: !(V.Vector B.Bit)
  }

p = 12000017 -- from http://compoasso.free.fr/primelistweb/page/prime/liste_online_en.php

getP :: Word32
getP = p

--
-- Create an empty Bloom filter with given capacity w and number of hash functions k
empty :: Word64 -> Int -> Int -> BloomFilter
empty seed m k
    | m > fromIntegral p = error $ "BloomFilter: m must be less than or equal to p (currently " ++ (show p) ++")... update p in BloomFilter.hs to support larger m"
    | otherwise =
        let s = pureMT seed
            getOneHash s =
                let (a, s') = samplePure (Uniform 1 (p - 1)) s
                    (b, s'') = samplePure (Uniform 0 (p - 1)) s'
                in Just ((a, b), s'')
            hashes = take k $ L.unfoldr getOneHash (pureMT seed)
            d = V.replicate m (B.Bit False)
        in BloomFilter
            { bfM = m
            , bfK = k
            , bfHashes = hashes
            , bfData = d
            }

getIndex :: Word32 -> Int -> (Word32, Word32) -> Int
getIndex x m (a, b) = fromIntegral $ ((a * x + b) `mod` p) `mod` fromIntegral m

insert :: Word32 -> BloomFilter -> BloomFilter
insert key bf =
  let updates = fmap ((,B.Bit True) . getIndex key (bfM bf)) (bfHashes bf)
      d' = bfData bf V.// updates
  in bf { bfData = d' }

member :: Word32 -> BloomFilter -> Bool
member key bf = bfHashes bf
  & fmap (B.unBit . (V.!) (bfData bf) . getIndex key (bfM bf))
  & L.foldl' (&&) True

clear :: BloomFilter -> BloomFilter
clear bf = bf { bfData = V.replicate (bfM bf) (B.Bit False) }

