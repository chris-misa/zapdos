{-
 - Simulated LPM match-action table
 -}

{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DeriveGeneric #-}

module MatchActionTable
  ( MAT
  , Prefix(..)
  , build
  , extract
  , apply
  , update
  , append
  , getIdx
  , replaceIdx
  ) where

import Data.Function ((&))
import Data.Word
import Data.Bits
import Data.Maybe

import qualified Data.Vector as V
import qualified Data.Vector.Mutable as MV
import Data.Vector ((!), (//))

import GHC.Generics (Generic)
import Data.Vector.Strategies (NFData)

-- 
-- Local modules
--
import Packets (ipv4_to_string, maskForBits)
import Common

-- 
-- Type parameters:
-- v - type of value stored for each key
-- m - type of per-packet metadata
--
data MAT v m = MAT
  { matKey :: m -> Word32
  , matUpdate :: Prefix -> m -> v -> (m, v)
  , matIndex :: !PrefixTree
  , matTable :: !(V.Vector (Prefix, v)) -- store as separate vectors instead of vector of tuples?
  }

data Prefix = Prefix !Word32 !Int
  deriving Generic
instance NFData Prefix
instance Show Prefix where
  show (Prefix k j) = ipv4_to_string k ++ "/" ++ show j

--
-- Build new table for given prefixes and initial values
--
build :: forall m v .
     (m -> Word32)                -- key extraction function
  -> (Prefix -> m -> v -> (m, v)) -- update function
  -> V.Vector (Prefix, v)         -- vector of prefixes and initial values
  -> MAT v m
build key update tbl = MAT
  { matKey = key
  , matUpdate = update
  , matIndex = index
  , matTable = tbl
  }
  where index :: PrefixTree
        index = V.ifoldl' addOne EmptyTree tbl

        addOne :: PrefixTree -> Int -> (Prefix, v) -> PrefixTree
        addOne tree idx (pfx, _) = prefixTreeBuild tree pfx idx

--
-- Update table data
--
update :: MAT v m -> V.Vector (Prefix, v) -> MAT v m
update m tbl = m
  { matIndex = index
  , matTable = tbl
  }
  where index :: PrefixTree
        index = V.ifoldl' addOne EmptyTree tbl

        addOne :: PrefixTree -> Int -> (Prefix, v) -> PrefixTree
        addOne tree idx (pfx, _) = prefixTreeBuild tree pfx idx

--
-- Append to table data
-- Note: assumes that new prefixes are disjoint w.r.t. previous prefixes
--
append :: MAT v m -> V.Vector (Prefix, v) -> MAT v m
append m newTbl = m
  { matIndex = index
  , matTable = matTable m V.++ newTbl
  }
  where index :: PrefixTree
        index = V.ifoldl' addOne (matIndex m) newTbl

        offset :: Int
        offset = V.length (matTable m)

        addOne :: PrefixTree -> Int -> (Prefix, v) -> PrefixTree
        addOne tree idx (pfx, _) = prefixTreeBuild tree pfx (idx + offset)

--
-- Extract the current state of the table
--
extract :: MAT v m -> V.Vector (Prefix, v)
extract = matTable

--
-- Return the prefix and value at given index
--
getIdx :: MAT v m -> Int -> (Prefix, v)
getIdx m idx = matTable m V.! idx

--
-- Replace given index with given prefix, value
--
replaceIdx :: MAT v m -> Int -> (Prefix, v) -> MAT v m
replaceIdx m idx  (newPfx, newVal) =
  let (oldPfx, _) = matTable m V.! idx
      index' = prefixTreeBuild (prefixTreeRemove (matIndex m) oldPfx) newPfx idx

      table' = matTable m V.// [(idx, (newPfx, newVal))]
  in m { matIndex = index', matTable = table' }

-- 
-- Update the MAT for the given packet metadata
--
apply :: forall v m . m -> MAT v m -> (m, MAT v m)
apply pkt tbl =
  case prefixTreeLookup (matIndex tbl) (matKey tbl pkt) of
    Just (pfx, idx) -> doApply pfx idx
    Nothing -> (pkt, tbl)
  where doApply :: Prefix -> Int -> (m, MAT v m)
        doApply pfx idx =
          let d = matTable tbl
              (_, val) = d ! idx
              (!pkt', !val') = matUpdate tbl pfx pkt val
              -- d' = d // [(idx, (pfx, val'))]
              !d' = V.modify (\v -> MV.write v idx (pfx, val')) d
          in (pkt', tbl { matTable = d' })

{-# INLINE apply #-}

-- TODO: update this to use defs from NewPrefixTree.hs

--
-- Internal nodes have nothing, leaves have Just idx where idx is a pointer
-- to the prefix's entry in the main table
--
data PrefixTree = EmptyTree
                | Node !Prefix !(Maybe Int) !PrefixTree !PrefixTree

instance Show PrefixTree where
  show EmptyTree = "EmptyTree"
  show (Node pfx s left right) =
    "(" ++ show pfx 
      ++ " " ++ (if isNothing s then show s else "(" ++ show s ++ ")")
      ++ " " ++ show left ++ " " ++ show right ++ ")"

prefixTreeRemove :: PrefixTree -> Prefix -> PrefixTree
prefixTreeRemove EmptyTree _ = EmptyTree
prefixTreeRemove oldNode@(Node (Prefix k j) s EmptyTree EmptyTree) (Prefix k' j')
  | k == k' && j == j' = EmptyTree
  | otherwise = oldNode
prefixTreeRemove (Node (Prefix k j) s l r) pfx@(Prefix k' j')
  | k == k' && j == j' = Node (Prefix k j) Nothing l r
  | otherwise =
    let l' = prefixTreeRemove l pfx
        r' = prefixTreeRemove r pfx
    in case (l', r') of
      (EmptyTree, EmptyTree) -> EmptyTree -- have to remove this node if both children would be empty to avoid empty leaves
      _ -> Node (Prefix k j) s  l' r'


prefixTreeBuild :: PrefixTree -> Prefix -> Int -> PrefixTree
prefixTreeBuild tree (Prefix _ (-1)) _ = tree -- ignores special length -1 prefixes so we can pass in-active prefixes that won't match anything
prefixTreeBuild EmptyTree (Prefix k j) s = Node (Prefix k j) (Just s) EmptyTree EmptyTree
prefixTreeBuild oldNode@(Node (Prefix k j) s l r) (Prefix k' j') s' =
  let d = firstDiffBit k k'
      isDisjoint = j == j' || (d <= j && d <= j')
      newIsSubnet = not isDisjoint && j < j'
      newIsSupnet = not isDisjoint && j' < j
  in
    if k == k' && j == j' -- Should be equivalent to version with d > 32
    then case s of
          Nothing -> Node (Prefix k j) (Just s') l r
          Just _ -> error $ "Tried to add duplicate prefix to prefix tree: " ++ show (Prefix k' j')
    else if isDisjoint
    then let d' = d - 1 in
      if k < k'
      then Node (Prefix (preserveUpperBits k d') d') Nothing oldNode (Node (Prefix k' j') (Just s') EmptyTree EmptyTree)
      else Node (Prefix (preserveUpperBits k d') d') Nothing (Node (Prefix k' j') (Just s') EmptyTree EmptyTree) oldNode
    else
    if newIsSubnet
    then if (k' `shiftR` (32 - (j + 1))) .&. 1 == 0
      then Node (Prefix k j) s (prefixTreeBuild l (Prefix k' j') s') r
      else Node (Prefix k j) s l (prefixTreeBuild r (Prefix k' j') s')
    else
    if newIsSupnet
    then if k < k'
      then Node (Prefix k' j') (Just s') oldNode EmptyTree
      else Node (Prefix k' j') (Just s') EmptyTree oldNode
    else
    error "We missed a case in buildTree!"

prefixTreeLookup :: PrefixTree -> Word32 -> Maybe (Prefix, Int)
prefixTreeLookup (Node (Prefix k j) (Just s) EmptyTree EmptyTree) k' =
  if k .&. maskForBits j == k' .&. maskForBits j
  then Just (Prefix k j, s)
  else Nothing
prefixTreeLookup (Node (Prefix k j) (Just s) l r) k'
  | j >= 32 || j < 0 = error $ "Prefix tree is broken: extends beyond 32 bits. Found when looking up " ++ show (Prefix k j)
  | otherwise =
  if k .&. maskForBits j == k' .&. maskForBits j
  then
    let childResult =
          if (k' `shiftR` (32 - (j + 1))) .&. 1 == 0
          then prefixTreeLookup l k'
          else prefixTreeLookup r k'
    in case childResult of
      Just res -> Just res
      Nothing -> Just (Prefix k j, s)
  else Nothing
prefixTreeLookup (Node (Prefix k j) Nothing EmptyTree EmptyTree) k' = error "prefixTreeLookup found empty leaf node!"
prefixTreeLookup (Node (Prefix k j) Nothing l r) k'
  | j >= 32 || j < 0 = error $ "Prefix tree is broken (Nothing case): extends beyond 32 bits. Found whe looking up " ++ show (Prefix k j)
  | otherwise =
  if k .&. maskForBits j == k' .&. maskForBits j
  then
    if (k' `shiftR` (32 - (j + 1))) .&. 1 == 0
    then prefixTreeLookup l k'
    else prefixTreeLookup r k'
  else Nothing
prefixTreeLookup EmptyTree _ = Nothing

