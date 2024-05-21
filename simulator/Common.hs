{-# LANGUAGE DeriveGeneric #-}

module Common where

import Data.Bits
import Data.Word
import Data.Function ((&))
import qualified Data.List as L

import GHC.Generics (Generic)
import Data.Vector.Strategies (NFData)

import qualified Packets as P

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

-- For multi-protocol resp/req diff, we need to keep track of a vector of response and request counts

data RespReq = RespReq !Int !Int
  deriving Generic
instance NFData RespReq

data RespReqList = RespReqList
  { rrListDNS :: !RespReq
  , rrListNTP :: !RespReq
  , rrListSSDP :: !RespReq
  , rrListTCP :: !RespReq
  } deriving Generic
instance NFData RespReqList

zeroRespReqList :: RespReqList
zeroRespReqList = RespReqList z z z z
  where z = RespReq 0 0

-- Return a list of increments for each considered response / request type
getRespReqIncr :: P.Packet -> (RespReqList, RespReqList)
getRespReqIncr p = (resps, reqs)
  where resps = RespReqList
            (RespReq dnsResp 0)
            (RespReq ntpResp 0)
            (RespReq ssdpResp 0)
            (RespReq tcpResp 0)
        reqs = RespReqList
            (RespReq 0 dnsReq)
            (RespReq 0 ntpReq)
            (RespReq 0 ssdpReq)
            (RespReq 0 tcpReq)
        dnsResp = if P.has_udp p && P.udp_sport p == 53 then 1 else 0
        dnsReq  = if P.has_udp p && P.udp_dport p == 53 then 1 else 0
        ntpResp = if P.has_udp p && P.udp_sport p == 123 then 1 else 0
        ntpReq  = if P.has_udp p && P.udp_dport p == 123 then 1 else 0
        ssdpResp = if P.has_udp p && P.udp_sport p == 1900 then 1 else 0
        ssdpReq  = if P.has_udp p && P.udp_dport p == 1900 then 1 else 0

        -- TCP (for syn flood) is a bit different (notion of response and request is kind of flipped)
        tcpFlags = if P.has_tcp p then P.tcp_flags p else 0
        tcpResp = if tcpFlags .&. P.tcp_syn /= 0 && tcpFlags .&. P.tcp_ack == 0 then 1 else 0
        tcpReq  = if tcpFlags .&. P.tcp_syn /= 0 && tcpFlags .&. P.tcp_ack /= 0 then 1 else 0

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

