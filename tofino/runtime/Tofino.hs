{-
 - Module for all Tofino gRPC-specific definitions
 -}

{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedLists #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE BangPatterns #-}

module Tofino
  ( TofinoState
  , clearAll
  , tsIncrClientId
  , getTofinoState
  , writeStaticDefaults
  , updateMonitorSlots
  , resultReqs
  , collectPrefixMap
  , getBenignPrefixMap
  , clearLookback
  , startMonitoringPrefixes
  , flagAsAttack
  , readPrefixFeatures
  ) where

import Data.Function ((&))
import Data.Text.Internal.Lazy (Text)
import Data.Word
import Data.Maybe
import Data.Bits
import qualified Data.List as L
import qualified Data.Vector as V
import qualified Data.Vector.Generic.Mutable as MV
import qualified Data.Vector.Unboxed as BV -- BV is for bit-vectors (using Data.Bit from bitvec package)
import qualified Data.Bit as BV
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BS (fromStrict, toStrict)
import qualified Data.Binary.Put as P
import qualified Data.Binary.Get as G
import qualified Control.Concurrent as CC
import Control.Concurrent.MVar
import System.Environment
import System.IO
import Control.Monad (join, when)
import Control.Arrow ((***), first)
import Network.Socket
import Network.Socket.ByteString

import qualified Data.HashMap.Strict as M
import qualified Data.Aeson as JSON
import qualified Data.Aeson.KeyMap as JSON
-- import Data.Digest.CRC32 (crc32)
import System.Clock
import System.Random.Mersenne.Pure64 (pureMT, PureMT)
import Immutable.Shuffle (shuffle)

import Bfruntime
import Network.GRPC.HighLevel.Generated
import Network.GRPC.LowLevel.GRPC (GRPCIOError)
import Proto3.Suite.Types (Enumerated(..))
import Google.Rpc.Status (Status(..))

import Common

{-

TODO: need a single state struct that holds the RPC config, sockets, idmaps, etc. needed for the core rpcs....

-}

defaultClientConfig :: ClientConfig
defaultClientConfig = ClientConfig
  { clientServerEndpoint = "localhost:50052"
  , clientArgs = []
  , clientSSLConfig = Nothing
  , clientAuthority = Nothing
  }

defaultTargetDevice :: TargetDevice
defaultTargetDevice = TargetDevice
  { targetDeviceDeviceId = 0
  , targetDevicePipeId = 0xFFFF -- seems like PIPE_ID_ALL = 0xFFFF
  , targetDeviceDirection = 0
  , targetDevicePrsrId = 0
  }

-- Name of the assured features p4 program loaded in switchd
defaultP4Name :: Text
defaultP4Name = "assured_features_tna"

--
-- Client id used in all bfruntime gRPCs
--
defaultClientId :: Word32
defaultClientId = 0

--
-- Send and receive packet-ferries for result requests via CPU port
--
-- have to add both ip address on the switch iface with ip a add x/y dev iface
-- and l2 addr using arp -s ipAddr macAddr
-- seems like this has to be re-done everytime the link flaps from reloading the p4 program...
--

data ResultReqState = ResultReqState
  { rrsSock :: Socket
  }

resultReqInit :: PortNumber -> HostAddress -> IO ResultReqState
resultReqInit resultReqPort resultReqAddr = withSocketsDo $ do
  s <- socket AF_INET Datagram defaultProtocol
  connect s (SockAddrInet resultReqPort resultReqAddr)
  return $ ResultReqState
    { rrsSock = s
    }

defaultResultReqPort :: PortNumber
defaultResultReqPort = 5555

defaultResultReqAddr :: HostAddress
defaultResultReqAddr = tupleToHostAddress (192, 168, 1, 1)


data TofinoState = TofinoState
  { tsClientConfig :: ClientConfig
  , tsTargetDevice :: TargetDevice
  , tsP4Name :: Text
  , tsClientId :: Word32
  , tsForwardingPipelineConfig :: ForwardingPipelineConfig
  , tsIdMap :: IdMap
  , tsResultReqState :: ResultReqState
  }

getTofinoState :: IO TofinoState
getTofinoState = do
  let clientConfig = defaultClientConfig -- TODO: pass these in from config file or command line?
      targetDevice = defaultTargetDevice
      p4Name = defaultP4Name
      clientId = defaultClientId
      resultReqPort = defaultResultReqPort
      resultReqAddr = defaultResultReqAddr
      
  pipeConf <- getForwardingPipeline clientConfig targetDevice p4Name clientId
  let idMap = extractIds pipeConf
  
  resultReqState <- resultReqInit resultReqPort resultReqAddr
  
  return $ TofinoState
    { tsClientConfig = clientConfig
    , tsTargetDevice = targetDevice
    , tsP4Name = p4Name
    , tsClientId = clientId
    , tsForwardingPipelineConfig = pipeConf
    , tsIdMap = idMap
    , tsResultReqState = resultReqState
    }
    
tsIncrClientId :: TofinoState -> TofinoState
tsIncrClientId s = s { tsClientId = tsClientId s + 1 }

--
-- Constants defined in assured_features_tna.p4
--
rrdiff_none     :: Word32
rrdiff_dns_req  :: Word32
rrdiff_dns_res  :: Word32
rrdiff_ntp_req  :: Word32
rrdiff_ntp_res  :: Word32
rrdiff_ssdp_req :: Word32
rrdiff_ssdp_res :: Word32
rrdiff_tcp_req  :: Word32
rrdiff_tcp_res  :: Word32

rrdiff_none     = 0
rrdiff_dns_req  = 1
rrdiff_dns_res  = 2
rrdiff_ntp_req  = 3
rrdiff_ntp_res  = 4
rrdiff_ssdp_req = 5
rrdiff_ssdp_res = 6
rrdiff_tcp_req  = 7
rrdiff_tcp_res  = 8


inactive_mode :: Word8
inactive_mode = 0

pre_attack_mode :: Word8
pre_attack_mode = 1

active_attack_mode :: Word8
active_attack_mode = 2


-- The id for counter and register index keys in counter or register tables
-- Seems to be constant for the whole bfrt_info json so we just define it as a constant here...
counter_index :: Word32
counter_index = 65556

register_index :: Word32
register_index = 65557

-- Data ids for counter's bytes and packets fields
-- Also seem to be constant

counter_spec_bytes :: Word32
counter_spec_bytes = 65553

counter_spec_pkts :: Word32
counter_spec_pkts = 65554

default_rpc_timeout :: Int
default_rpc_timeout = 10


getForwardingPipeline :: ClientConfig -> TargetDevice -> Text -> Word32 -> IO ForwardingPipelineConfig
getForwardingPipeline clientConfig targetDevice p4Name clientId = withGRPCClient clientConfig $ \client -> do
  BfRuntime{..} <- bfRuntimeClient client

  let req = GetForwardingPipelineConfigRequest
        { getForwardingPipelineConfigRequestDeviceId = targetDeviceDeviceId targetDevice
        , getForwardingPipelineConfigRequestClientId = clientId
        }
  ClientNormalResponse resp _meta1 _meta2 _status _details
    <- bfRuntimeGetForwardingPipelineConfig (ClientNormalRequest req default_rpc_timeout [])

  let conf = getForwardingPipelineConfigResponseConfig resp
             & V.filter ((== p4Name) . forwardingPipelineConfigP4Name)

  case conf of
    [c] -> return c
    _ -> error $ "Failed to fined pipeline config with p4_name == \"" ++ show p4Name ++ "\"... is the p4 program running?"




-- For keeping track of table ids
data TableIds = TableIds
  { tableIdSelectBySrc :: Word32
  , tableIdClearSrc :: Word32
  , tableIdSelectByDst :: Word32
  , tableIdClearDst :: Word32
  , tableIdPktsFrom :: Word32
  , tableIdBytesFrom :: Word32
  , tableIdPktsTo :: Word32
  , tableIdBytesTo :: Word32
  , tableIdRrDiffClassify :: Word32
  , tableIdChildIdx :: Word32
  , tableIdChildBits :: Word32

  , tableIdMinLength :: Word32
  , tableIdMaxLength :: Word32
  , tableIdAveLength :: Word32
  
  , tableIdPrevTime :: Word32
  , tableIdMinIPG :: Word32
  , tableIdMaxIPG :: Word32
  , tableIdAveIPG :: Word32

  , tableIdChildBitmap :: Word32
  
  , tableIdLookback32 :: Word32

  , tableIdDNSReq :: Word32
  , tableIdDNSRes :: Word32
  , tableIdNTPReq :: Word32
  , tableIdNTPRes :: Word32
  , tableIdSSDPReq :: Word32
  , tableIdSSDPRes :: Word32
  , tableIdTCPReq :: Word32
  , tableIdTCPRes :: Word32

  -- , tableIdMode :: Word32

  } deriving (Show)

defaultTableIds :: TableIds
defaultTableIds = TableIds 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

-- For keeping track of action ids
data ActionIds = ActionIds
  { actionIdSelectBySrc :: Word32
  , actionIdSelectByDst :: Word32
  , actionIdSetRrDiffType :: Word32
  , actionIdGetChildIdxSlash4 :: Word32
  , actionIdGetChildIdxSlash8 :: Word32
  , actionIdGetChildIdxSlash12 :: Word32
  , actionIdGetChildIdxSlash16 :: Word32
  , actionIdGetChildIdxSlash20 :: Word32
  , actionIdGetChildIdxSlash24 :: Word32
  , actionIdGetChildIdxSlash28 :: Word32
  , actionIdGetChildIdxSlash32 :: Word32
  , actionIdGetChildBits :: Word32
  , actionIdFlagAsAttack :: Word32
  } deriving (Show)

defaultActionIds :: ActionIds
defaultActionIds = ActionIds 0 0 0 0 0 0 0 0 0 0 0 0 0

data IdMap = IdMap
  { idMapTables :: TableIds
  , idMapActions :: ActionIds
  } deriving (Show)

-- Note: it looks like the key fields and action data fields index from 1 and are more or less fixed so we don't need to keep track of them seperately from bfrt info...

extractIds :: ForwardingPipelineConfig -> IdMap
extractIds conf =
  let JSON.Object bfrt =
        case JSON.decode $ BS.fromStrict $ forwardingPipelineConfigBfruntimeInfo conf of
          Just j -> j
          Nothing -> error "Failed to decode bfruntime_info json chunk in returned forwarding pipeline config!"

      tables =
        case JSON.lookup "tables" bfrt of
          Just (JSON.Array j) -> j
          Just _ -> error "Key \"tables\" in bfruntime_info json is not an array!"
          Nothing -> error "Failed to find \"tables\" key in bfruntime_info json!"

      oneTable (JSON.Object tbl) =
        let name = case JSON.lookup "name" tbl of
              Just (JSON.String n) -> n
              Just _ -> error "Value for \"name\" key in table entry in bfruntime_info json is not a string!"
              Nothing -> error "Failed to find \"name\" key in table entry in bfruntime_info json!"
            id = case JSON.lookup "id" tbl of
              Just (JSON.Number i) -> i
              Just _ -> error "Value for \"id\" key in table entry in bfruntime_info json is not a number!"
              Nothing -> error "Failed to find \"id\" key in table entry in bfruntime_info json!"
        in (name, id)
      oneTable _ = error "Non-object in \"tables\" array in bfruntime_info json!"

      accumulateTableIds tableIds (name, id) =
        case name of
          "pipe.SwitchIngress.select_by_src_tbl" -> tableIds { tableIdSelectBySrc = round id }
          "pipe.SwitchIngress.clearSrc" -> tableIds { tableIdClearSrc = round id }
          "pipe.SwitchIngress.select_by_dst_tbl" -> tableIds { tableIdSelectByDst = round id }
          "pipe.SwitchIngress.clearDst" -> tableIds { tableIdClearDst = round id }
          "pipe.SwitchIngress.pktsFrom" -> tableIds { tableIdPktsFrom = round id }
          "pipe.SwitchIngress.bytesFrom" -> tableIds { tableIdBytesFrom = round id }
          "pipe.SwitchIngress.pktsTo" -> tableIds { tableIdPktsTo = round id }
          "pipe.SwitchIngress.bytesTo" -> tableIds { tableIdBytesTo = round id }
          "pipe.SwitchIngress.rrDiff_classify_tbl" -> tableIds { tableIdRrDiffClassify = round id }
          "pipe.SwitchIngress.child_idx_tbl" -> tableIds { tableIdChildIdx = round id }
          "pipe.SwitchIngress.child_bits_tbl" -> tableIds { tableIdChildBits = round id }
          "pipe.SwitchIngress.minLength" -> tableIds { tableIdMinLength = round id }
          "pipe.SwitchIngress.maxLength" -> tableIds { tableIdMaxLength = round id }
          "pipe.SwitchIngress.aveLength" -> tableIds { tableIdAveLength = round id }
          "pipe.SwitchIngress.prevTime" -> tableIds { tableIdPrevTime = round id }
          "pipe.SwitchIngress.minIPG" -> tableIds { tableIdMinIPG = round id }
          "pipe.SwitchIngress.maxIPG" -> tableIds { tableIdMaxIPG = round id }
          "pipe.SwitchIngress.aveIPG" -> tableIds { tableIdAveIPG = round id }
          "pipe.SwitchIngress.childBitmap" -> tableIds { tableIdChildBitmap = round id }
          "pipe.SwitchIngress.lookback32" -> tableIds { tableIdLookback32 = round id }
          "pipe.SwitchIngress.dnsResp" -> tableIds { tableIdDNSRes = round id }
          "pipe.SwitchIngress.dnsReq" -> tableIds { tableIdDNSReq = round id }
          "pipe.SwitchIngress.ntpResp" -> tableIds { tableIdNTPRes = round id }
          "pipe.SwitchIngress.ntpReq" -> tableIds { tableIdNTPReq = round id }
          "pipe.SwitchIngress.ssdpResp" -> tableIds { tableIdSSDPRes = round id }
          "pipe.SwitchIngress.ssdpReq" -> tableIds { tableIdSSDPReq = round id }
          "pipe.SwitchIngress.tcpResp" -> tableIds { tableIdTCPRes = round id }
          "pipe.SwitchIngress.tcpReq" -> tableIds { tableIdTCPReq = round id }
          _ -> tableIds

      allTableIds = tables
        & V.map oneTable
        & V.foldl accumulateTableIds defaultTableIds

      extractActions (JSON.Object tbl) =
        let actions = case JSON.lookup "action_specs" tbl of
              Just (JSON.Array as) -> as
              Just _ -> error "Value for \"action_specs\" key in table object in bfruntime_info json is not an array!"
              Nothing -> [] -- Some tables don't have any "action_specs"
            oneAction (JSON.Object act) =
              let name = case JSON.lookup "name" act of
                    Just (JSON.String n) -> n
                    Just _ -> error "Value for \"name\" key in \"action_specs\" object is not a string!"
                    Nothing -> error "Failed to find \"name\" key in \"action_specs\" object!"
                  id = case JSON.lookup "id" act of
                    Just (JSON.Number i) -> i
                    Just _ -> error "Value for \"id\" key in \"action_specs\" object is not a number!"
                    Nothing -> error "Failed to find \"id\" key in \"action_specs\" object!"
              in (name, id)
            oneAction _ = error "Non-object in \"action_specs\" key in table object in bfruntime_info json!"
        in V.map oneAction actions
      extractActions _ = error "Non-object in \"tables\" array in bfruntime_info json when trying to extract actions!"

      accumulateActionIds actionIds (name, id) =
        case name of
          "SwitchIngress.select_by_src" -> actionIds { actionIdSelectBySrc = round id }
          "SwitchIngress.select_by_dst" -> actionIds { actionIdSelectByDst = round id }
          "SwitchIngress.set_rrDiffType" -> actionIds { actionIdSetRrDiffType = round id }
          "SwitchIngress.get_child_idx_slash4" -> actionIds { actionIdGetChildIdxSlash4 = round id }
          "SwitchIngress.get_child_idx_slash8" -> actionIds { actionIdGetChildIdxSlash8 = round id }
          "SwitchIngress.get_child_idx_slash12" -> actionIds { actionIdGetChildIdxSlash12 = round id }
          "SwitchIngress.get_child_idx_slash16" -> actionIds { actionIdGetChildIdxSlash16 = round id }
          "SwitchIngress.get_child_idx_slash20" -> actionIds { actionIdGetChildIdxSlash20 = round id }
          "SwitchIngress.get_child_idx_slash24" -> actionIds { actionIdGetChildIdxSlash24 = round id }
          "SwitchIngress.get_child_idx_slash28" -> actionIds { actionIdGetChildIdxSlash28 = round id }
          "SwitchIngress.get_child_idx_slash32" -> actionIds { actionIdGetChildIdxSlash32 = round id }
          "SwitchIngress.get_child_bits" -> actionIds { actionIdGetChildBits = round id }
          "SwitchIngress.flag_as_attack" -> actionIds { actionIdFlagAsAttack = round id }
          _ -> actionIds

      allActionIds = tables
        & V.concatMap extractActions
        & V.foldl accumulateActionIds defaultActionIds
        
  in IdMap allTableIds allActionIds





--
-- Utilities for building exact-match keys
--   i is the key field index (starts from 1 normally)
--   k is the exact-match key value for field i
--
exactKeyField32 :: Word32 -> Word32 -> KeyField
exactKeyField32 i k = KeyField
  { keyFieldFieldId = i
  , keyFieldMatchType = Just $ KeyFieldMatchTypeExact $ KeyField_Exact $ BS.toStrict $ P.runPut $ P.putWord32be k
  }

exactKeyField16 :: Word32 -> Word16 -> KeyField
exactKeyField16 i k = KeyField
  { keyFieldFieldId = i
  , keyFieldMatchType = Just $ KeyFieldMatchTypeExact $ KeyField_Exact $ BS.toStrict $ P.runPut $ P.putWord16be k
  }

exactKeyField8 :: Word32 -> Word8 -> KeyField
exactKeyField8 i k = KeyField
  { keyFieldFieldId = i
  , keyFieldMatchType = Just $ KeyFieldMatchTypeExact $ KeyField_Exact $ BS.singleton k
  }

exactKeyField4 :: Word32 -> Word8 -> KeyField
exactKeyField4 i k = KeyField
  { keyFieldFieldId = i
  , keyFieldMatchType = Just $ KeyFieldMatchTypeExact $ KeyField_Exact $ BS.singleton k
  }



--
-- Utilities for building ternary-match keys
--   i is the key field index (1-based)
--   k is the key value
--   m is the mask value
--
ternaryKeyField32 :: Word32 -> Word32 -> Word32 -> KeyField
ternaryKeyField32 i k m = KeyField
  { keyFieldFieldId = i
  , keyFieldMatchType = Just $ KeyFieldMatchTypeTernary $ KeyField_Ternary
                        { keyField_TernaryValue = BS.toStrict $ P.runPut $ P.putWord32be k
                        , keyField_TernaryMask = BS.toStrict $ P.runPut $ P.putWord32be m
                        }
  }

ternaryKeyField16 :: Word32 -> Word16 -> Word16 -> KeyField
ternaryKeyField16 i k m = KeyField
  { keyFieldFieldId = i
  , keyFieldMatchType = Just $ KeyFieldMatchTypeTernary $ KeyField_Ternary
                        { keyField_TernaryValue = BS.toStrict $ P.runPut $ P.putWord16be k
                        , keyField_TernaryMask = BS.toStrict $ P.runPut $ P.putWord16be m
                        }
  }

ternaryKeyField8 :: Word32 -> Word8 -> Word8 -> KeyField
ternaryKeyField8 i k m = KeyField
  { keyFieldFieldId = i
  , keyFieldMatchType = Just $ KeyFieldMatchTypeTernary $ KeyField_Ternary
                        { keyField_TernaryValue = BS.singleton k
                        , keyField_TernaryMask = BS.singleton m
                        }
  }



--
-- Utilities for building "bytes"-type DataFields
--   i is the key field index (1-based)
--   x is the data for that field
--
streamDataField32 :: Word32 -> Word32 -> DataField
streamDataField32 i x = DataField
  { dataFieldFieldId = i
  , dataFieldValue = Just $ DataFieldValueStream $ BS.toStrict $ P.runPut $ P.putWord32be x
  }

streamDataField16 :: Word32 -> Word16 -> DataField
streamDataField16 i x = DataField
  { dataFieldFieldId = i
  , dataFieldValue = Just $ DataFieldValueStream $ BS.toStrict $ P.runPut $ P.putWord16be x
  }

streamDataField8 :: Word32 -> Word8 -> DataField
streamDataField8 i x = DataField
  { dataFieldFieldId = i
  , dataFieldValue = Just $ DataFieldValueStream $ BS.singleton x
  }


--
-- Utility for building insert updates
--   i is the table id
--   k is the TableKey specification of where to write in the table
--   d is the TableData specification of what to write
--
tableEntryInsert :: Word32 -> TableKey -> TableData -> Update
tableEntryInsert i k d =
  let ent = TableEntry
        { tableEntryTableId = i
        , tableEntryValue = Just (TableEntryValueKey k)
        , tableEntryData = Just d
        , tableEntryIsDefaultEntry = False
        , tableEntryTableReadFlag = Nothing
        , tableEntryTableModIncFlag = Nothing
        , tableEntryEntryTgt = Nothing
        , tableEntryTableFlags = Nothing
        }
  in Update
     { updateType = Enumerated (Right Update_TypeINSERT)
     , updateEntity = Just $ Entity { entityEntity = Just $ EntityEntityTableEntry ent }
     }

--
-- Utility for building delete updates
--   i is the table id
--   k is the TableKey specification of which key to delete from table i
--
tableEntryDelete :: Word32 -> TableKey -> Update
tableEntryDelete i k =
  let ent = TableEntry
        { tableEntryTableId = i
        , tableEntryValue = Just (TableEntryValueKey k)
        , tableEntryData = Nothing
        , tableEntryIsDefaultEntry = False
        , tableEntryTableReadFlag = Nothing
        , tableEntryTableModIncFlag = Nothing
        , tableEntryEntryTgt = Nothing
        , tableEntryTableFlags = Nothing
        }
  in Update
     { updateType = Enumerated (Right Update_TypeDELETE)
     , updateEntity = Just $ Entity { entityEntity = Just $ EntityEntityTableEntry ent }
     }


--
-- Utility for building modify updates
--   i is the table id
--   k is the TableKey specification of where to write in the table
--   d is the TableData specification of what to write
--
tableEntryModify :: Word32 -> TableKey -> TableData -> Update
tableEntryModify i k d =
  let ent = TableEntry
        { tableEntryTableId = i
        , tableEntryValue = Just (TableEntryValueKey k)
        , tableEntryData = Just d
        , tableEntryIsDefaultEntry = False
        , tableEntryTableReadFlag = Nothing
        , tableEntryTableModIncFlag = Nothing
        , tableEntryEntryTgt = Nothing
        , tableEntryTableFlags = Nothing
        }
  in Update
     { updateType = Enumerated (Right Update_TypeMODIFY)
     , updateEntity = Just $ Entity { entityEntity = Just $ EntityEntityTableEntry ent }
     }

--
-- Utility to reset all entries of a table to default values
--   i is the table id
--
-- For some reason won't work with counter tables except with CONTINUE_ON_ERROR atomicity...
--
tableReset :: Word32 -> Update
tableReset i =
  let ent = TableEntry
        { tableEntryTableId = i
        , tableEntryValue = Nothing
        , tableEntryData = Nothing
        , tableEntryIsDefaultEntry = False
        , tableEntryTableReadFlag = Nothing
        , tableEntryTableModIncFlag = Nothing
        , tableEntryEntryTgt = Nothing
        , tableEntryTableFlags = Nothing
        }
  in Update        
     { updateType = Enumerated (Right Update_TypeDELETE)
     , updateEntity = Just $ Entity { entityEntity = Just $ EntityEntityTableEntry ent }
     }

--
-- Utility for building register write updates
--   i is the register table id
--   k is the index of which register cell to write
--   d is the value to write in the k-th cell
--
registerWrite32 :: Word32 -> Word32 -> Word32 -> Update
registerWrite32 i k d =
  let ent = TableEntry
        { tableEntryTableId = i
        , tableEntryValue = Just (TableEntryValueKey $ TableKey [ exactKeyField32 register_index k ])
        , tableEntryData = Just (TableData 0 [ streamDataField32 1 d ]) -- Seems like it just ignores action index here...
        , tableEntryIsDefaultEntry = False
        , tableEntryTableReadFlag = Nothing
        , tableEntryTableModIncFlag = Nothing
        , tableEntryEntryTgt = Nothing
        , tableEntryTableFlags = Nothing
        }
  in Update
     { updateType = Enumerated (Right Update_TypeMODIFY)
     , updateEntity = Just $ Entity { entityEntity = Just $ EntityEntityTableEntry ent }
     }



--
-- Write default values for all static control memories required for proper functioning of ZAPDOS p4 program
-- Also enters pre-attack mode
--
writeStaticDefaults :: ZAPDOSConfig -> TofinoState -> IO ()
writeStaticDefaults conf state = withGRPCClient (tsClientConfig state) $ \client -> do
  BfRuntime{..} <- bfRuntimeClient client

  let idmap = tsIdMap state

      -- rrDiff table: DNS reflection
  
      rrDiffDNSReqKey = TableKey
        [ exactKeyField8 1 17 -- ipv4.protocol
        , ternaryKeyField16 2 0 0 -- l4.sport
        , ternaryKeyField16 3 53 0xFFFF -- l4.dport
        , ternaryKeyField8 4 0 0 -- tcp.flags
        ]
      rrDiffDNSReqData = TableData (actionIdSetRrDiffType $ idMapActions idmap) [ streamDataField32 1 rrdiff_dns_req ]
      rrDiffDNSReq = tableEntryInsert (tableIdRrDiffClassify $ idMapTables idmap) rrDiffDNSReqKey rrDiffDNSReqData

      rrDiffDNSResKey = TableKey
        [ exactKeyField8 1 17
        , ternaryKeyField16 2 53 0xFFFF -- l4.sport
        , ternaryKeyField16 3 0 0 -- l4.dport
        , ternaryKeyField8 4 0 0 -- tcp.flags
        ]
      rrDiffDNSResData = TableData (actionIdSetRrDiffType $ idMapActions idmap) [ streamDataField32 1 rrdiff_dns_res ]
      rrDiffDNSRes = tableEntryInsert (tableIdRrDiffClassify $ idMapTables idmap) rrDiffDNSResKey rrDiffDNSResData

      -- rrDiff table: NTP reflection
  
      rrDiffNTPReqKey = TableKey
        [ exactKeyField8 1 17
        , ternaryKeyField16 2 0 0 -- l4.sport
        , ternaryKeyField16 3 123 0xFFFF -- l4.dport
        , ternaryKeyField8 4 0 0 -- tcp.flags
        ]
      rrDiffNTPReqData = TableData (actionIdSetRrDiffType $ idMapActions idmap) [ streamDataField32 1 rrdiff_ntp_req ]
      rrDiffNTPReq = tableEntryInsert (tableIdRrDiffClassify $ idMapTables idmap) rrDiffNTPReqKey rrDiffNTPReqData

      rrDiffNTPResKey = TableKey
        [ exactKeyField8 1 17
        , ternaryKeyField16 2 123 0xFFFF -- l4.sport
        , ternaryKeyField16 3 0 0 -- l4.dport
        , ternaryKeyField8 4 0 0 -- tcp.flags
        ]
      rrDiffNTPResData = TableData (actionIdSetRrDiffType $ idMapActions idmap) [ streamDataField32 1 rrdiff_ntp_res ]
      rrDiffNTPRes = tableEntryInsert (tableIdRrDiffClassify $ idMapTables idmap) rrDiffNTPResKey rrDiffNTPResData

      -- rrDiff table: SSDP reflection
  
      rrDiffSSDPReqKey = TableKey
        [ exactKeyField8 1 17
        , ternaryKeyField16 2 0 0 -- l4.sport
        , ternaryKeyField16 3 1900 0xFFFF -- l4.dport
        , ternaryKeyField8 4 0 0 -- tcp.flags
        ]
      rrDiffSSDPReqData = TableData (actionIdSetRrDiffType $ idMapActions idmap) [ streamDataField32 1 rrdiff_ssdp_req ]
      rrDiffSSDPReq = tableEntryInsert (tableIdRrDiffClassify $ idMapTables idmap) rrDiffSSDPReqKey rrDiffSSDPReqData

      rrDiffSSDPResKey = TableKey
        [ exactKeyField8 1 17
        , ternaryKeyField16 2 1900 0xFFFF -- l4.sport
        , ternaryKeyField16 3 0 0 -- l4.dport
        , ternaryKeyField8 4 0 0 -- tcp.flags
        ]
      rrDiffSSDPResData = TableData (actionIdSetRrDiffType $ idMapActions idmap) [ streamDataField32 1 rrdiff_ssdp_res ]
      rrDiffSSDPRes = tableEntryInsert (tableIdRrDiffClassify $ idMapTables idmap) rrDiffSSDPResKey rrDiffSSDPResData

      -- rrDiff table: SYN flood
  
      rrDiffTCPReqKey = TableKey
        [ exactKeyField8 1 6
        , ternaryKeyField16 2 0 0 -- l4.sport
        , ternaryKeyField16 3 0 0 -- l4.dport
        , ternaryKeyField8 4 18 18 -- tcp.flags
        ]
      rrDiffTCPReqData = TableData (actionIdSetRrDiffType $ idMapActions idmap) [ streamDataField32 1 rrdiff_tcp_req ]
      rrDiffTCPReq = tableEntryInsert (tableIdRrDiffClassify $ idMapTables idmap) rrDiffTCPReqKey rrDiffTCPReqData

      rrDiffTCPResKey = TableKey
        [ exactKeyField8 1 17
        , ternaryKeyField16 2 0 0 -- l4.sport
        , ternaryKeyField16 3 0 0 -- l4.dport
        , ternaryKeyField8 4 2 18 -- tcp.flags
        ]
      rrDiffTCPResData = TableData (actionIdSetRrDiffType $ idMapActions idmap) [ streamDataField32 1 rrdiff_tcp_res ]
      rrDiffTCPRes = tableEntryInsert (tableIdRrDiffClassify $ idMapTables idmap) rrDiffTCPResKey rrDiffTCPResData


      -- Child idx table

      getChildIdx4Key = TableKey [ exactKeyField8 1 4 ]
      getChildIdx4Data = TableData (actionIdGetChildIdxSlash4 $ idMapActions idmap) []
      getChildIdx4 = tableEntryInsert (tableIdChildIdx $ idMapTables idmap) getChildIdx4Key getChildIdx4Data

      getChildIdx8Key = TableKey [ exactKeyField8 1 8 ]
      getChildIdx8Data = TableData (actionIdGetChildIdxSlash8 $ idMapActions idmap) []
      getChildIdx8 = tableEntryInsert (tableIdChildIdx $ idMapTables idmap) getChildIdx8Key getChildIdx8Data

      getChildIdx12Key = TableKey [ exactKeyField8 1 12 ]
      getChildIdx12Data = TableData (actionIdGetChildIdxSlash12 $ idMapActions idmap) []
      getChildIdx12 = tableEntryInsert (tableIdChildIdx $ idMapTables idmap) getChildIdx12Key getChildIdx12Data

      getChildIdx16Key = TableKey [ exactKeyField8 1 16 ]
      getChildIdx16Data = TableData (actionIdGetChildIdxSlash16 $ idMapActions idmap) []
      getChildIdx16 = tableEntryInsert (tableIdChildIdx $ idMapTables idmap) getChildIdx16Key getChildIdx16Data

      getChildIdx20Key = TableKey [ exactKeyField8 1 20 ]
      getChildIdx20Data = TableData (actionIdGetChildIdxSlash20 $ idMapActions idmap) []
      getChildIdx20 = tableEntryInsert (tableIdChildIdx $ idMapTables idmap) getChildIdx20Key getChildIdx20Data

      getChildIdx24Key = TableKey [ exactKeyField8 1 24 ]
      getChildIdx24Data = TableData (actionIdGetChildIdxSlash24 $ idMapActions idmap) []
      getChildIdx24 = tableEntryInsert (tableIdChildIdx $ idMapTables idmap) getChildIdx24Key getChildIdx24Data

      getChildIdx28Key = TableKey [ exactKeyField8 1 28 ]
      getChildIdx28Data = TableData (actionIdGetChildIdxSlash28 $ idMapActions idmap) []
      getChildIdx28 = tableEntryInsert (tableIdChildIdx $ idMapTables idmap) getChildIdx28Key getChildIdx28Data

      getChildIdx32Key = TableKey [ exactKeyField8 1 32 ]
      getChildIdx32Data = TableData (actionIdGetChildIdxSlash32 $ idMapActions idmap) []
      getChildIdx32 = tableEntryInsert (tableIdChildIdx $ idMapTables idmap) getChildIdx32Key getChildIdx32Data
  

      -- Child index table (pre-computes mult part of add and mult computation required for child indices in the child bitmap)
      
      childBitsKey i = TableKey [ exactKeyField4 1 (fromIntegral i)]
      childBitsData i = TableData (actionIdGetChildBits $ idMapActions idmap) [ streamDataField16 1 (1 `shiftL` i) ]
      childBits i = tableEntryInsert (tableIdChildBits $ idMapTables idmap) (childBitsKey i) (childBitsData i)
      
      updates = V.fromList $
        [ rrDiffDNSReq
        , rrDiffDNSRes
        , rrDiffNTPReq
        , rrDiffNTPRes
        , rrDiffSSDPReq
        , rrDiffSSDPRes
        , rrDiffTCPReq
        , rrDiffTCPRes
        ] ++
        [ getChildIdx4
        , getChildIdx8
        , getChildIdx12
        , getChildIdx16
        , getChildIdx20
        , getChildIdx24
        , getChildIdx28
        , getChildIdx32
        ] ++
        [ childBits i | i <- [0..child_bitmap_width-1]]
        where child_bitmap_width = 2 ^ confBitsPerEpoch conf
        

      req = WriteRequest
        { writeRequestTarget = Just (tsTargetDevice state)
        , writeRequestClientId = tsClientId state
        , writeRequestUpdates = updates
        , writeRequestAtomicity = Enumerated (Right WriteRequest_AtomicityCONTINUE_ON_ERROR)
        , writeRequestP4Name = tsP4Name state
        }

  preResp <- bfRuntimeWrite (ClientNormalRequest req default_rpc_timeout [])

  let resp = case preResp of
        ClientNormalResponse r _ _ _ _ -> r
        ClientErrorResponse err -> error $ "bfRuntimeWrite failed in writeStaticDefaults with: " ++ show err

  let errs = writeResponseStatus resp
  
  if V.length errs == 0 then
    return () -- putStrLn "writeStaticDefaults no errors"
    else do
    putStrLn "writeStaticDefaults returned errors:"
    V.sequence $ V.map (putStrLn . show) errs
    return ()

  return ()


--
-- Clear all tables related to Zapdos
--
clearAll :: TofinoState -> IO ()
clearAll state = withGRPCClient (tsClientConfig state) $ \client -> do
  BfRuntime{..} <- bfRuntimeClient client

  let idmap = tsIdMap state
  
      req = WriteRequest
        { writeRequestTarget = Just (tsTargetDevice state)
        , writeRequestClientId = tsClientId state
        , writeRequestUpdates =
          [ tableReset $ tableIdLookback32 $ idMapTables $ tsIdMap state
          , tableReset $ tableIdSelectBySrc $ idMapTables $ tsIdMap state
          , tableReset $ tableIdClearSrc $ idMapTables $ tsIdMap state
          , tableReset $ tableIdSelectByDst $ idMapTables $ tsIdMap state
          , tableReset $ tableIdClearDst $ idMapTables $ tsIdMap state
          , tableReset $ tableIdPktsFrom $ idMapTables $ tsIdMap state
          , tableReset $ tableIdBytesFrom $ idMapTables $ tsIdMap state
          , tableReset $ tableIdPktsTo $ idMapTables $ tsIdMap state
          , tableReset $ tableIdBytesTo $ idMapTables $ tsIdMap state
          , tableReset $ tableIdRrDiffClassify $ idMapTables $ tsIdMap state
          , tableReset $ tableIdChildIdx $ idMapTables $ tsIdMap state
          , tableReset $ tableIdChildBits $ idMapTables $ tsIdMap state
          , tableReset $ tableIdMinLength $ idMapTables $ tsIdMap state
          , tableReset $ tableIdMaxLength $ idMapTables $ tsIdMap state
          , tableReset $ tableIdAveLength $ idMapTables $ tsIdMap state
          , tableReset $ tableIdPrevTime $ idMapTables $ tsIdMap state
          , tableReset $ tableIdMinIPG $ idMapTables $ tsIdMap state
          , tableReset $ tableIdMaxIPG $ idMapTables $ tsIdMap state
          , tableReset $ tableIdAveIPG $ idMapTables $ tsIdMap state
          , tableReset $ tableIdChildBitmap $ idMapTables $ tsIdMap state
          , tableReset $ tableIdLookback32 $ idMapTables $ tsIdMap state
          , tableReset $ tableIdDNSReq $ idMapTables $ tsIdMap state
          , tableReset $ tableIdDNSRes $ idMapTables $ tsIdMap state
          , tableReset $ tableIdNTPReq $ idMapTables $ tsIdMap state
          , tableReset $ tableIdNTPRes $ idMapTables $ tsIdMap state
          , tableReset $ tableIdSSDPReq $ idMapTables $ tsIdMap state
          , tableReset $ tableIdSSDPRes $ idMapTables $ tsIdMap state
          , tableReset $ tableIdTCPReq $ idMapTables $ tsIdMap state
          , tableReset $ tableIdTCPRes $ idMapTables $ tsIdMap state
          ]
        , writeRequestAtomicity = Enumerated (Right WriteRequest_AtomicityCONTINUE_ON_ERROR)
        , writeRequestP4Name = tsP4Name state
        }

  preResp <- bfRuntimeWrite (ClientNormalRequest req default_rpc_timeout [])

  let resp = case preResp of
        ClientNormalResponse r _ _ _ _ -> r
        ClientErrorResponse err -> error $ "bfRuntimeWrite failed in clearAll with: " ++ show err

  let errs = writeResponseStatus resp
  
  when (V.length errs /= 0) $ do
    putStrLn "clearAll returned errors:"
    V.sequence $ V.map (putStrLn . show) errs
    return ()

  return ()

--
-- Clears the lookback hardware Bloom filter
--
clearLookback :: TofinoState -> IO ()
clearLookback state = withGRPCClient (tsClientConfig state) $ \client -> do
  BfRuntime{..} <- bfRuntimeClient client

  let idmap = tsIdMap state
  
      req = WriteRequest
        { writeRequestTarget = Just (tsTargetDevice state)
        , writeRequestClientId = tsClientId state
        , writeRequestUpdates = [ tableReset $ tableIdLookback32 $ idMapTables $ tsIdMap state ]
        , writeRequestAtomicity = Enumerated (Right WriteRequest_AtomicityCONTINUE_ON_ERROR)
        , writeRequestP4Name = tsP4Name state
        }

  preResp <- bfRuntimeWrite (ClientNormalRequest req default_rpc_timeout [])

  let resp = case preResp of
        ClientNormalResponse r _ _ _ _ -> r
        ClientErrorResponse err -> error $ "bfRuntimeWrite failed in preAttackMode with: " ++ show err

  let errs = writeResponseStatus resp
  
  when (V.length errs /= 0) $ do
    putStrLn "preAttackMode returned errors:"
    V.sequence $ V.map (putStrLn . show) errs
    return ()

  return ()

--
-- Update batch of prefix monitoring slots in hardware
-- oldPfxs is a vector of prefixes to remove
-- newPfxs is a vector of prefixes to add and their indices
--
updateMonitorSlots :: ZAPDOSConfig -> TofinoState -> V.Vector Prefix -> V.Vector Prefix -> V.Vector (Prefix, Int) -> IO ()
updateMonitorSlots conf state newReports oldPfxs newPfxs = withGRPCClient (tsClientConfig state) $ \client -> do
  BfRuntime{..} <- bfRuntimeClient client

  let idmap = tsIdMap state

      deletes = V.concatMap (\(Prefix p l) ->
                               let oldKey = TableKey [ ternaryKeyField32 1 p (maskForBits l) ]
                               in [ tableEntryDelete (tableIdSelectBySrc $ idMapTables idmap) oldKey
                                  , tableEntryDelete (tableIdSelectByDst $ idMapTables idmap) oldKey
                                  ]
                            ) oldPfxs

      inserts = V.concatMap (\(Prefix p l, idx) ->
                               let newKey = TableKey [ ternaryKeyField32 1 p (maskForBits l) ]
                                   newSrcData = TableData (actionIdSelectBySrc $ idMapActions idmap)
                                                [ streamDataField32 1 (fromIntegral idx)
                                                , streamDataField8 2 (fromIntegral l)
                                                ]
                                   newDstData = TableData (actionIdSelectByDst $ idMapActions idmap)
                                                [ streamDataField32 1 (fromIntegral idx)
                                                , streamDataField8 2 (fromIntegral l)
                                                ]

                                   idxKey = TableKey [ exactKeyField32 register_index (fromIntegral idx) ]
                                   idxData = TableData 0 [ streamDataField8 1 1 ]
                               in [ tableEntryInsert (tableIdSelectBySrc $ idMapTables idmap) newKey newSrcData
                                  , tableEntryInsert (tableIdClearSrc $ idMapTables idmap) idxKey idxData
                                  , tableEntryInsert (tableIdSelectByDst $ idMapTables idmap) newKey newDstData
                                  , tableEntryInsert (tableIdClearDst $ idMapTables idmap) idxKey idxData
                                  ]
                            ) newPfxs

      reports = V.map (\(Prefix p l) ->
                         let newKey = TableKey [ ternaryKeyField32 1 p (maskForBits l) ]
                             newData = TableData (actionIdFlagAsAttack $ idMapActions idmap) []
                         in tableEntryInsert (tableIdSelectBySrc $ idMapTables idmap) newKey newData
                      ) newReports


      req = WriteRequest
        { writeRequestTarget = Just (tsTargetDevice state)
        , writeRequestClientId = tsClientId state
        , writeRequestUpdates = deletes V.++ inserts V.++ reports
        , writeRequestAtomicity = Enumerated (Right WriteRequest_AtomicityCONTINUE_ON_ERROR)
        , writeRequestP4Name = tsP4Name state
        }

  preResp <- bfRuntimeWrite (ClientNormalRequest req default_rpc_timeout [])

  let resp = case preResp of
        ClientNormalResponse r _ _ _ _ -> r
        ClientErrorResponse err -> error $ "bfRuntimeWrite failed in updateMonitorSlot with: " ++ show err

  let errs = writeResponseStatus resp
  
  if V.length errs == 0 then
    -- putStrLn $ "updateMonitorSlot removed: " ++ show oldPfx ++ ", added: " ++ show newPfx
    return ()
    else do
    putStrLn "updateMonitorSlot returned errors:"
    V.sequence $ V.map (putStrLn . show) errs
    return ()

  return ()



flagAsAttack :: TofinoState -> Prefix -> IO ()
flagAsAttack state (Prefix p l) = withGRPCClient (tsClientConfig state) $ \client -> do
  BfRuntime{..} <- bfRuntimeClient client

  let idmap = tsIdMap state

      newKey = TableKey [ ternaryKeyField32 1 p (maskForBits l) ]
      newData = TableData (actionIdFlagAsAttack $ idMapActions idmap) []

      req = WriteRequest
        { writeRequestTarget = Just (tsTargetDevice state)
        , writeRequestClientId = tsClientId state
        , writeRequestUpdates = [ tableEntryInsert (tableIdSelectBySrc $ idMapTables idmap) newKey newData ]
        , writeRequestAtomicity = Enumerated (Right WriteRequest_AtomicityCONTINUE_ON_ERROR)
        , writeRequestP4Name = tsP4Name state
        }

  preResp <- bfRuntimeWrite (ClientNormalRequest req default_rpc_timeout [])

  let resp = case preResp of
        ClientNormalResponse r _ _ _ _ -> r
        ClientErrorResponse err -> error $ "bfRuntimeWrite failed in flagAsAttack with: " ++ show err

  let errs = writeResponseStatus resp
  
  if V.length errs == 0 then
    -- putStrLn $ "updateMonitorSlot removed: " ++ show oldPfx ++ ", added: " ++ show newPfx
    return ()
    else do
    putStrLn "flagAsAttack returned errors:"
    V.sequence $ V.map (putStrLn . show) errs
    return ()

  return ()




{-

Update order:

1. read features using resultReq (seems like these packets do also get counted, but this should be ok if we only read once and always reset after...) ---> seems like rrDiff strangely do get incremented by something...
2. make decision
3. update

Other notes:

Just use digests to gradually report lookback filters to CPU...!


Known bug potential: result_req packets increment counters.
non-trivial to solve because in some cases would require more than 2 condition operations
should be ok because we only send one result_req packet, then reset the prefix.

Also, rrDiff seems to get incremented on both sides by result_req packets, but this shouldn't impact the results.
-}

--
-- Of course bursts of UDP packets like this probably require increases recv UDP buffer...
-- (using net.core.rmem_{max,default}=16777216 seems to work up to 100 prefixes...)
-- (0.0047 s for 100 prefixes
resultReqs :: TofinoState -> V.Vector Int -> IO (V.Vector (Int, Features))
resultReqs ts ids = do
  let state = tsResultReqState ts
      req idx = (BS.toStrict $ P.runPut $ P.putWord32be $ fromIntegral idx) `BS.append` BS.replicate 78 0 -- TODO: would be nice if requests could just be the index ...

  flip V.mapM_ ids $ \idx -> do
    n <- send (rrsSock state) (req idx)
    when (n /= BS.length (req idx)) $ do
      putStrLn "Warning: failed to send entire result request packet!"

  -- putStrLn $ "recv'd " ++ show (BS.length res) ++ " bytes"
  let parseResultReq = do
        idx <- G.getWord32be
        pktsFrom <- G.getWord32be
        pktsTo <- G.getWord32be
        bytesFrom <- G.getWord32be
        bytesTo <- G.getWord32be
        minLen <- G.getWord32be
        maxLen <- G.getWord32be
        aveLen <- G.getWord32be
        minIPG <- G.getWord32be
        maxIPG <- G.getWord32be
        aveIPG <- G.getWord32be
        dnsRes <- G.getWord32be
        dnsReq <- G.getWord32be
        ntpRes <- G.getWord32be
        ntpReq <- G.getWord32be
        ssdpRes <- G.getWord32be
        ssdpReq <- G.getWord32be
        tcpRes <- G.getWord32be
        tcpReq <- G.getWord32be
        childBitmap <- G.getWord16be
        clearSrc <- G.getWord8 -- if this is 1 then there were no packets from this prefix since last clear -> return zeroFeatures
        clearDst <- G.getWord8 -- if this is 1 then there were no packets to this prefix since last clear -> zero out dst-based features
        let f = if clearSrc /= 0 then
                  zeroFeatures
                else if clearDst /= 0 then
                       zeroFeatures
                       { fPktsFrom = fromIntegral pktsFrom
                       , fPktsTo = 0
                       , fBytesFrom = fromIntegral bytesFrom
                       , fBytesTo = 0
                       , fMinIPG = fromIntegral minIPG / 1000000000.0
                       , fMaxIPG = fromIntegral maxIPG / 1000000000.0
                       , fAveIPG = fromIntegral aveIPG / 1000000000.0
                       , fMinLen = fromIntegral minLen
                       , fMaxLen = fromIntegral maxLen
                       , fAveLen = fromIntegral aveLen
                       , fRespReqList = RespReqList
                                        { rrListDNS = RespReq (fromIntegral dnsRes) 0
                                        , rrListNTP = RespReq (fromIntegral ntpRes) 0
                                        , rrListSSDP = RespReq (fromIntegral ssdpRes) 0
                                        , rrListTCP = RespReq (fromIntegral tcpRes) 0
                                        }
                       , fChildBitmap = fromIntegral childBitmap
                       }
                     else
                       zeroFeatures
                       { fPktsFrom = fromIntegral pktsFrom
                       , fPktsTo = fromIntegral pktsTo
                       , fBytesFrom = fromIntegral bytesFrom
                       , fBytesTo = fromIntegral bytesTo
                       , fMinIPG = fromIntegral minIPG / 1000000000.0
                       , fMaxIPG = fromIntegral maxIPG / 1000000000.0
                       , fAveIPG = fromIntegral aveIPG / 1000000000.0
                       , fMinLen = fromIntegral minLen
                       , fMaxLen = fromIntegral maxLen
                       , fAveLen = fromIntegral aveLen
                       , fRespReqList = RespReqList
                                        { rrListDNS = RespReq (fromIntegral dnsRes) (fromIntegral dnsReq)
                                        , rrListNTP = RespReq (fromIntegral ntpRes) (fromIntegral ntpReq)
                                        , rrListSSDP = RespReq (fromIntegral ssdpRes) (fromIntegral ssdpReq)
                                        , rrListTCP = RespReq (fromIntegral tcpRes) (fromIntegral tcpReq)
                                        }
                       , fChildBitmap = fromIntegral childBitmap
                       }
        return (fromIntegral idx, f)

  res <- flip V.mapM ids $ \_  -> do
    r <- recv (rrsSock state) 4096 -- TODO: should really time out and resend request...
    return $ G.runGet parseResultReq (BS.fromStrict r)

  return res



-- need to keep this around for the lookback read for now...
-- only used for benchmarking
tableReadAll :: Word32 -> Entity
tableReadAll i =
  let ent = TableEntry
        { tableEntryTableId = i
        , tableEntryValue = Nothing -- Giving Nothing here appears to read all keys (or rows) in the table
        , tableEntryData = Nothing
        , tableEntryIsDefaultEntry = False
        , tableEntryTableReadFlag = Nothing
        , tableEntryTableModIncFlag = Nothing
        , tableEntryEntryTgt = Nothing
        , tableEntryTableFlags = Just $ TableFlags
                                 { tableFlagsFromHw = True
                                 , tableFlagsKeyOnly = False
                                 , tableFlagsModDel = False
                                 , tableFlagsResetTtl = False
                                 , tableFlagsResetStats = False
                                 }
        }
  in Entity { entityEntity = Just $ EntityEntityTableEntry ent }


--
-- Utility to extract a single-field 32-bit exact-match key
--
extractKey32 :: Word32 -> Maybe TableEntryValue -> Maybe Word32
extractKey32 i (Just (TableEntryValueKey (TableKey key))) =
  case key V.!? 0 of
    Just (KeyField i (Just (KeyFieldMatchTypeExact (KeyField_Exact k))))
      | i == i -> Just $ G.runGet G.getWord32be (BS.fromStrict k)
      | otherwise -> Nothing
    _ -> Nothing
extractKey32 _ Nothing = Nothing

--
-- Utilities to extract data fields
--
extractData64 :: Word32 -> Maybe TableData -> Maybe Word64
extractData64 i (Just td) =
  case V.filter ((== i) . dataFieldFieldId) (tableDataFields td) V.!? 0 of
    Just (DataField { dataFieldValue = Just (DataFieldValueStream d) }) -> Just $ G.runGet G.getWord64be (BS.fromStrict d)
    _ -> Nothing
extractData64 _ Nothing = Nothing

extractData32 :: Word32 -> Maybe TableData -> Maybe Word32
extractData32 i (Just td) =
  case V.filter ((== i) . dataFieldFieldId) (tableDataFields td) V.!? 0 of
    Just (DataField { dataFieldValue = Just (DataFieldValueStream d) }) -> Just $ G.runGet G.getWord32be (BS.fromStrict d)
    _ -> Nothing
extractData32 _ Nothing = Nothing

extractData8 :: Word32 -> Maybe TableData -> Maybe Word8
extractData8 i (Just td) =
  case V.filter ((== i) . dataFieldFieldId) (tableDataFields td) V.!? 0 of
    Just (DataField { dataFieldValue = Just (DataFieldValueStream d) }) -> Just $ BS.head d
    _ -> Nothing
extractData8 _ Nothing = Nothing



bindToProgram :: TofinoState -> IO ()
bindToProgram state = withGRPCClient (tsClientConfig state) $ \client -> do
  BfRuntime{..} <- bfRuntimeClient client

  let conf = ForwardingPipelineConfig
        { forwardingPipelineConfigP4Name = tsP4Name state
        , forwardingPipelineConfigBfruntimeInfo = ""
        , forwardingPipelineConfigProfiles = []
        }
      req = SetForwardingPipelineConfigRequest
        { setForwardingPipelineConfigRequestDeviceId = 0
        , setForwardingPipelineConfigRequestClientId = tsClientId state
        , setForwardingPipelineConfigRequestAction = Enumerated $ Right SetForwardingPipelineConfigRequest_ActionBIND
        , setForwardingPipelineConfigRequestDevInitMode = Enumerated $ Right SetForwardingPipelineConfigRequest_DevInitModeFAST_RECONFIG
        , setForwardingPipelineConfigRequestBasePath = ""
        , setForwardingPipelineConfigRequestConfig = [conf]
        }
  ClientNormalResponse resp _meta1 _meta2 _status _details
    <- bfRuntimeSetForwardingPipelineConfig (ClientNormalRequest req default_rpc_timeout [])

  -- putStrLn $ "bind response: " ++ show resp
  return ()

--
-- Pass an empty MVar as killSwitch, then put () into it to trigget stream termination
--
collectPrefixMap :: ZAPDOSConfig -> TofinoState -> Int -> MVar () -> MVar (PrefixMap) -> IO ()
collectPrefixMap conf state timeout killSwitch prefixesVar = withGRPCClient (tsClientConfig state) $ \client -> do
  BfRuntime{..} <- bfRuntimeClient client
  putMVar prefixesVar M.empty
  let sub = Subscribe
        { subscribeIsMaster = False
        , subscribeDeviceId = 0
        , subscribeNotifications = Just $ Subscribe_Notifications
                                   { subscribe_NotificationsEnableLearnNotifications = True
                                   , subscribe_NotificationsEnableIdletimeoutNotifications = False
                                   , subscribe_NotificationsEnablePortStatusChangeNotifications = False
                                   , subscribe_NotificationsEnableEntryActiveNotifications = False
                                   }
        , subscribeStatus = Nothing
        }
      req = StreamMessageRequest
        { streamMessageRequestClientId = tsClientId state
        , streamMessageRequestUpdate = Just $ StreamMessageRequestUpdateSubscribe sub
        }
      handler _clientCall _meta1 recv send writesDone = do
        res <- send req
        case res of
          Left err -> putStrLn $ "send digest request in collectPrefixMap returned error: " ++ show err
          Right () -> return () -- putStrLn $ "Send digest request"

        CC.forkIO $ do
          () <- takeMVar killSwitch
          writesDone
          return ()
          
        let processUpdate (StreamMessageResponseUpdateSubscribe subscribe) =
              case subscribeStatus subscribe of
                Just (Status { statusCode = sc })
                  | sc == 0 -> do
                      -- putStrLn "Subscribe successfull, binding..."
                      bindToProgram state
                _ -> putStrLn "Subscribe failed in collectPrefixMap!"
            processUpdate (StreamMessageResponseUpdateDigest dl) = do
              let !newSrcs = digestListData dl
                    & V.map (\td -> extractData32 1 (Just td))
                    & V.filter isJust
                    & V.map fromJust
              prefixes <- takeMVar prefixesVar
              let processOneSrc pm src =
                    let update (Just v) = Just (v + 1)
                        update Nothing = Just 1
                    in foldl (\pm' l -> M.alter update (Prefix (preserveUpperBits src l) l) pm') pm
                       ([ 0, (confBitsPerEpoch conf) .. 32] :: [Int])
              -- let !prefixes' = V.foldl (\pm src -> M.insert (Prefix src 32) 1 pm) prefixes newSrcs
              let !prefixes' = V.foldl processOneSrc prefixes newSrcs

              putMVar prefixesVar prefixes'
              return () -- It seems like we should send an ack here, but they're not actually supported on the server...

            processUpdate _ = putStrLn "Unused stream message response update type"
                
            handleOne = do
              res <- recv
              case res of
                Left err -> do
                  putStrLn $ "Client reader got error: " ++ show err
                  return ()
                Right (Just (StreamMessageResponse (Just rr))) -> do
                  -- putStrLn $ "Client reader read: " ++ show rr
                  processUpdate rr
                  handleOne
                Right (Just (StreamMessageResponse Nothing)) -> do
                  putStrLn "Client reader got StreamMessageResponse Nothing ...? (ignoring)"
                  handleOne
                Right Nothing -> do
                  -- putStrLn "Client reader got end of stream"
                  return ()

        handleOne

  !res <- bfRuntimeStreamChannel (ClientBiDiRequest (timeout + 60) [] handler) -- the question is how to make this not timeout...
  case res of
    ClientBiDiResponse _meta1 _status _details -> return () -- putStrLn "Send bidi request handler request"
    ClientErrorResponse err -> putStrLn $ "Error trying to send ClientBiDiReqeust: " ++ show err

  return ()


--
-- Blocks for dur seconds to collect benign prefix map
-- (Assumes hardware is already in pre-attack mode after writeStaticDefaults)
--
getBenignPrefixMap :: ZAPDOSConfig -> TofinoState -> Int -> IO PrefixMap
getBenignPrefixMap conf state dur = do
  killSwitch <- newEmptyMVar
  result <- newEmptyMVar

  CC.forkIO $ collectPrefixMap conf state dur killSwitch result

  -- Have to clear lookback Bloom filter _after_ subscribing to digests because otherwise we miss digests of continuous sources...
  CC.threadDelay 5
  clearLookback state

    -- putStrLn "... started waiting for benign prefixes"
  startTime <- getTime Monotonic
  let wait = do
        curTime <- getTime Monotonic
        if toNanoSecs (diffTimeSpec curTime startTime) >= fromIntegral dur * 1000000000
          then return ()
          else do
          CC.threadDelay 50
          wait
  wait
  putMVar killSwitch ()
    -- putStrLn "... put () into killSwitch"

  pm <- takeMVar result

  -- return $ filloutPrefixMap pm
  return pm






-- This one's old, but useful for benchmarking
startMonitoringPrefixes :: ZAPDOSConfig -> TofinoState -> V.Vector Prefix -> IO ()
startMonitoringPrefixes conf state prefixes = withGRPCClient (tsClientConfig state) $ \client -> do
  let idmap = tsIdMap state
  
  BfRuntime{..} <- bfRuntimeClient client

  let selectBySrcKey (i, Prefix p l) = TableKey [ ternaryKeyField32 1 p (maskForBits l) ]
      selectBySrcData (i, Prefix p l) = TableData (actionIdSelectBySrc $ idMapActions idmap)
                                        [ streamDataField32 1 i, streamDataField8 2 (fromIntegral l) ]
      selectBySrc pfx = tableEntryInsert (tableIdSelectBySrc $ idMapTables idmap) (selectBySrcKey pfx) (selectBySrcData pfx)

      selectByDstKey (i, Prefix p l) = TableKey [ ternaryKeyField32 1 p (maskForBits l) ]
      selectByDstData (i, Prefix p l) = TableData (actionIdSelectByDst $ idMapActions idmap)
                                        [ streamDataField32 1 i, streamDataField8 2 (fromIntegral l) ]
      selectByDst pfx = tableEntryInsert (tableIdSelectByDst $ idMapTables idmap) (selectByDstKey pfx) (selectByDstData pfx)

      idxPrefixes = V.indexed prefixes & V.map (first fromIntegral)

      updates =
        [ tableReset (tableIdSelectBySrc $ idMapTables idmap), tableReset (tableIdSelectByDst $ idMapTables idmap) ]
        V.++ V.map selectBySrc idxPrefixes
        V.++ V.map selectByDst idxPrefixes
      req = WriteRequest
        { writeRequestTarget = Just (tsTargetDevice state)
        , writeRequestClientId = tsClientId state
        , writeRequestUpdates = updates
        , writeRequestAtomicity = Enumerated (Right WriteRequest_AtomicityCONTINUE_ON_ERROR)
        , writeRequestP4Name = tsP4Name state
        }

  preResp <- bfRuntimeWrite (ClientNormalRequest req default_rpc_timeout [])

  let resp = case preResp of
        ClientNormalResponse r _ _ _ _ -> r
        ClientErrorResponse err -> error $ "bfRuntimeWrite failed in startMonitoringPrefixes with: " ++ show err

  let errs = writeResponseStatus resp
  
  if V.length errs == 0 then
    putStrLn "startMonitoringPrefixes no errors"
    else do
    putStrLn "startMonitoringPrefixes returned errors:"
    V.sequence $ V.map (putStrLn . show) errs
    return ()

  return ()




-- also no longer used, but kept around for benchmarking
processReadResponse :: ZAPDOSConfig -> IdMap -> V.Vector (Prefix, Features) -> MVar (V.Vector (Prefix, Features)) -> ReadResponse -> IO ()
processReadResponse conf idmap prefixes featuresVar rr = do
  let res = prefixes
        & V.modify (\v ->
                       -- All stuffed in here so type inference is happy given the existential under V.modify (probably there exists a cleaner way to do this...)
                       -- Note also that we ignore indices larger than the expected number of prefixes because they are still reported even when smaller number of prefixes is selected...
                       let oneUpdate prevAction (Entity (Just ent)) = do
                             prevAction
                             case ent of
                               EntityEntityTableEntry e
                                 | tableEntryTableId e == tableIdPktsFrom (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         pkts = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fPktsFrom = pkts })
                                 | tableEntryTableId e == tableIdBytesFrom (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         bytes = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fBytesFrom = bytes })
                                 | tableEntryTableId e == tableIdPktsTo (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 counter_index (tableEntryValue e)
                                         pkts = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fPktsTo = pkts })
                                 | tableEntryTableId e == tableIdBytesTo (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 counter_index (tableEntryValue e)
                                         bytes = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fBytesTo = bytes })
                                     
                                 | tableEntryTableId e == tableIdMinLength (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         minLength = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fMinLen = minLength })
                                 | tableEntryTableId e == tableIdMaxLength (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         maxLength = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fMaxLen = maxLength })
                                 | tableEntryTableId e == tableIdAveLength (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         aveLength = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fAveLen = aveLength })
                                     
                                 | tableEntryTableId e == tableIdMinIPG (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         minIPG = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fMinIPG = minIPG })
                                 | tableEntryTableId e == tableIdMaxIPG (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         maxIPG = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fMaxIPG = maxIPG })
                                 | tableEntryTableId e == tableIdAveIPG (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         aveIPG = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fAveIPG = aveIPG })

                                 | tableEntryTableId e == tableIdDNSReq (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         req = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f@(Features { fRespReqList = rr@(RespReqList { rrListDNS = RespReq res _ })})) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fRespReqList = rr { rrListDNS = RespReq res req }})
                                 | tableEntryTableId e == tableIdDNSRes (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         res = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f@(Features { fRespReqList = rr@(RespReqList { rrListDNS = RespReq _ req })})) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fRespReqList = rr { rrListDNS = RespReq res req }})
                                 | tableEntryTableId e == tableIdNTPReq (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         req = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f@(Features { fRespReqList = rr@(RespReqList { rrListNTP = RespReq res _ })})) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fRespReqList = rr { rrListNTP = RespReq res req }})
                                 | tableEntryTableId e == tableIdNTPRes (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         res = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f@(Features { fRespReqList = rr@(RespReqList { rrListNTP = RespReq _ req })})) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fRespReqList = rr { rrListNTP = RespReq res req }})
                                 | tableEntryTableId e == tableIdSSDPReq (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         req = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f@(Features { fRespReqList = rr@(RespReqList { rrListSSDP = RespReq res _ })})) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fRespReqList = rr { rrListSSDP = RespReq res req }})
                                 | tableEntryTableId e == tableIdSSDPRes (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         res = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f@(Features { fRespReqList = rr@(RespReqList { rrListSSDP = RespReq _ req })})) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fRespReqList = rr { rrListSSDP = RespReq res req }})
                                 | tableEntryTableId e == tableIdTCPReq (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         req = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f@(Features { fRespReqList = rr@(RespReqList { rrListTCP = RespReq res _ })})) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fRespReqList = rr { rrListTCP = RespReq res req }})
                                 | tableEntryTableId e == tableIdTCPRes (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         res = fromIntegral $ fromJust $ extractData32 1 (tableEntryData e)
                                     when (idx < V.length prefixes) $ do
                                       (pfx, f@(Features { fRespReqList = rr@(RespReqList { rrListTCP = RespReq _ req })})) <- MV.read v idx
                                       MV.write v idx $ (pfx, f { fRespReqList = rr { rrListTCP = RespReq res req }})

                                 | tableEntryTableId e == tableIdChildBitmap (idMapTables idmap) -> do
                                     let idx = fromIntegral $ fromJust $ extractKey32 register_index (tableEntryValue e)
                                         bit = fromIntegral $ fromJust $ extractData8 1 (tableEntryData e)
                                         prefixIdx = idx `div` (2 ^ confBitsPerEpoch conf)
                                     if prefixIdx < V.length prefixes && bit /= 0 then do
                                       (pfx, f@(Features { fChildBitmap = bitmap })) <- MV.read v prefixIdx
                                       let bitmap' = bitmap .|. (1 `shiftL` (idx `mod` (2 ^ confBitsPerEpoch conf)))
                                       MV.write v prefixIdx $ (pfx, f { fChildBitmap = bitmap' })
                                       else
                                       return ()
                   
                                 | otherwise -> return ()
                               _ -> return ()
                       in V.foldl oneUpdate (return ()) (readResponseEntities rr)
                   )
  putMVar featuresVar res

readPrefixFeatures :: ZAPDOSConfig -> TofinoState -> V.Vector (Prefix, Features) -> IO (V.Vector (Prefix, Features))
readPrefixFeatures conf ts prefixes = withGRPCClient (tsClientConfig ts) $ \client -> do
  let idmap = tsIdMap ts
  BfRuntime{..} <- bfRuntimeClient client
  features <- newEmptyMVar
  let entities =
        [ tableReadAll $ tableIdPktsFrom $ idMapTables idmap
        , tableReadAll $ tableIdBytesFrom $ idMapTables idmap
        , tableReadAll $ tableIdPktsTo $ idMapTables idmap
        , tableReadAll $ tableIdBytesTo $ idMapTables idmap
        , tableReadAll $ tableIdMinLength $ idMapTables idmap
        , tableReadAll $ tableIdMaxLength $ idMapTables idmap
        , tableReadAll $ tableIdAveLength $ idMapTables idmap
        , tableReadAll $ tableIdMinIPG $ idMapTables idmap
        , tableReadAll $ tableIdMaxIPG $ idMapTables idmap
        , tableReadAll $ tableIdAveIPG $ idMapTables idmap
        , tableReadAll $ tableIdDNSReq $ idMapTables idmap
        , tableReadAll $ tableIdDNSRes $ idMapTables idmap
        , tableReadAll $ tableIdNTPReq $ idMapTables idmap
        , tableReadAll $ tableIdNTPRes $ idMapTables idmap
        , tableReadAll $ tableIdSSDPReq $ idMapTables idmap
        , tableReadAll $ tableIdSSDPRes $ idMapTables idmap
        , tableReadAll $ tableIdTCPReq $ idMapTables idmap
        , tableReadAll $ tableIdTCPRes $ idMapTables idmap
        , tableReadAll $ tableIdChildBitmap $ idMapTables idmap
        ]
      req = ReadRequest
        { readRequestTarget = Just (tsTargetDevice ts)
        , readRequestClientId = tsClientId ts
        , readRequestEntities = entities
        , readRequestP4Name = tsP4Name ts
        }
      reader _clientCall _meta1 recv = do
        res <- recv
        case res of
          Left err -> putStrLn $ "Client reader got error: " ++ show err
          Right (Just rr) -> processReadResponse conf idmap prefixes features rr
          Right Nothing -> putStrLn "Client reader got end of stream"

  resp
    <- bfRuntimeRead (ClientReaderRequest req 120 [] reader) -- reads take this long?

  case resp of
    ClientReaderResponse _meta1 _status _details -> return ()
    ClientErrorResponse err -> error $ "bfRuntimeWrite failed in startMonitoringPrefixes with: " ++ show err
    
  -- Wait for the reader to populate results, then return
  features' <- takeMVar features

  return features'
