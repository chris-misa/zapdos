{-
 - Simple random forest classifier
 - Designed to load forests fit by the R randomForest package
 - and as such does not provide fitting capabilities
 -}

{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module RandomForest where

import Data.Function ((&))
import GHC.Generics
import qualified Data.ByteString.Lazy as BL
import qualified Data.Vector as V
import qualified Data.List as L

import Data.Csv -- from cassava
import qualified Data.HashMap.Strict as M -- from unordered-containers
import Data.HashMap.Strict ((!))

data Tree = Node Tree Tree Int Double | Leaf Double
    deriving (Show)

type RandomForest = [Tree]

data TreeNode = TreeNode {
        left :: !Int,
        right :: !Int,
        var :: !Int,
        split :: !Double,
        status :: !Int,
        prediction :: !Double,
        k :: !Int
    }
    deriving (Generic, Show)

instance FromNamedRecord TreeNode

readModelFile :: String -> IO RandomForest
readModelFile filepath = do
    file <- BL.readFile filepath
    case decodeByName file of
        Left err -> do
            putStrLn err
            return []
        Right (_, v) -> do
            return (buildForest v)

buildForest :: V.Vector TreeNode -> RandomForest
buildForest nodes =
    buildForestRec nodes 1 []
    where buildForestRec :: V.Vector TreeNode -> Int -> RandomForest -> RandomForest
          buildForestRec nodes curK prev =
            let (treeNodes, theRest) = V.span ((==curK) . k) nodes
                newTree = buildTree treeNodes
            in case V.length theRest of
                0 -> newTree : prev
                _ -> buildForestRec theRest (curK + 1) (newTree : prev)

buildTree :: V.Vector TreeNode -> Tree
buildTree nodes = 
    let theMap = nodes & V.toList & zip [1..] & M.fromList
    in buildTreeRec theMap 1
    where buildTreeRec :: (M.HashMap Int TreeNode) -> Int -> Tree
          buildTreeRec theMap idx =
            let newNode = theMap ! idx
            in case status newNode of
                -3 -> Node (buildTreeRec theMap (left newNode)) (buildTreeRec theMap (right newNode)) (var newNode - 1) (split newNode)
                -1 -> Leaf (prediction newNode)


predictTree :: (V.Vector Double) -> Tree -> Double
predictTree features (Node l r v s)
    | features V.! v <= s = predictTree features l
    | otherwise = predictTree features r
predictTree features (Leaf x) = x

predict :: (V.Vector Double) -> RandomForest -> Double
predict features forest =
    let n = fromIntegral (length forest)
    in forest
        & fmap (predictTree features) -- TODO: this could be data-parallel!
        & L.foldl' (+) 0.0
        & (/ n)



