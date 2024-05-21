{-
 - Simple interface for reading packets
 - Uses `pcap` library to read pcap files
 - Exposes high level projections for extracting common header fiels
 -}
module Packets where

import Data.Word
import Data.Int
import Data.Bits
import Data.List
import Data.Function ((&))
import Data.Maybe
import Numeric
import Data.Hashable
import qualified Data.List as L

-- see: https://hackage.haskell.org/package/bytestring
import qualified Data.ByteString as B

-- see: https://hackage.haskell.org/package/pcap
import qualified Network.Pcap as P

-- see: https://hackage.haskell.org/package/binary
import Data.Binary.Get

maskForBits :: Int -> Word32
maskForBits n = (0xFFFFFFFF `shiftL` (32 - n)) .&. 0xFFFFFFFF

data LayerMap = LayerMap {
    ipv4 :: Maybe Int,
    tcp :: Maybe Int,
    udp :: Maybe Int,
    wlan :: Maybe Int
} deriving (Show)

emptyLayerMap = LayerMap { ipv4 = Nothing, tcp = Nothing, udp = Nothing, wlan = Nothing}

-- Packet is a tuple of
-- 1. packet time in microseconds
-- 2. map from layers to offsets
-- 3. ByteString of the packet's headers
type Packet = (Int64, LayerMap, B.ByteString)

data MACAddress = MAC B.ByteString deriving (Eq)

instance Show MACAddress where
    show (MAC b) =
        b & B.unpack & fmap (\p -> showHex p (addZero p)) & L.intercalate ":"
        where addZero p = if p < 0x10 then "0" else ""

instance Hashable MACAddress where
    hashWithSalt s (MAC b) = hashWithSalt s b

parsePacket :: P.Link -> P.PktHdr -> B.ByteString -> Maybe Packet
parsePacket dl hdr buf =
    case dl of
       P.DLT_EN10MB ->
            parseEther hdr buf
       P.DLT_RAW ->
            let lm = emptyLayerMap { ipv4 = Just 0 } in
            parseIP lm hdr buf
       P.DLT_IEEE802_11_RADIO -> 
            parseWlan hdr buf
       _ -> Nothing

parseEther :: P.PktHdr -> B.ByteString -> Maybe Packet
parseEther hdr buf =
    let ethertype = runGet getWord16be (buf & B.drop 12 & B.fromStrict) in
    case ethertype of
        0x0800 | B.length buf >= 34 -> parseIP (emptyLayerMap { ipv4 = Just 14 }) hdr buf
        0x86DD | B.length buf >= 34 -> parseIP (emptyLayerMap { ipv4 = Just 14 }) hdr buf
        0x8100 | B.length buf >= 38 -> parseIP (emptyLayerMap { ipv4 = Just 18 }) hdr buf
        _ -> Nothing

parseIP :: LayerMap -> P.PktHdr -> B.ByteString -> Maybe Packet
parseIP lm hdr buf =
    let ip = fromJust (ipv4 lm)
        ipversion = B.index buf ip `shiftR` 4
    in case ipversion of
        4 -> let proto = B.index buf (ip + 9)
                 (tcp, udp) = case proto of
                        6 | B.length buf - ip >= 40 -> (Just (ip + 20), Nothing)
                        17 | B.length buf - ip >= 28 -> (Nothing, Just (ip + 20))
                        _ -> (Nothing, Nothing)
             in Just (P.hdrTime hdr, lm {tcp = tcp, udp = udp}, buf)
        _ -> Nothing

parseWlan :: P.PktHdr -> B.ByteString -> Maybe Packet
parseWlan hdr buf =
    -- just skip the radiotap header for now
    let rtLen = runGet getWord16le (buf & B.drop 2 & B.fromStrict)
    in Just (P.hdrTime hdr, emptyLayerMap { wlan = Just (fromIntegral rtLen) }, buf)


-- Returns a function to create monadic actions to read the given pcap file into Packets
readPcapFile :: String -> IO (IO (Maybe Packet))
readPcapFile file = do
    handle <- P.openOffline file
    dl <- P.datalink handle
    return $ stepOne dl handle
    where stepOne :: P.Link -> P.PcapHandle -> IO (Maybe Packet)
          stepOne dl handle = do
              (hdr, buf) <- P.nextBS handle
              if B.length buf == 0
              then return Nothing
              else do
                let pkt = parsePacket dl hdr buf
                case pkt of
                    Just pkt -> return (Just pkt)
                    Nothing -> stepOne dl handle

livePcap :: String -> IO (IO (Maybe Packet))
livePcap device = do
    handle <- P.openLive device 1500 False 100000 -- last arg: timeout in microseconds
    dl <- P.datalink handle
    return $ stepOne dl handle
    where stepOne :: P.Link -> P.PcapHandle -> IO (Maybe Packet)
          stepOne dl handle = do
              (hdr, buf) <- P.nextBS handle
              if B.length buf == 0
              then return Nothing
              else do
                let pkt = parsePacket dl hdr buf
                case pkt of
                    Just pkt -> return (Just pkt)
                    Nothing -> stepOne dl handle

-- 
-- Generic projections
--

time :: Packet -> Int64
time (t, _, _) = t

-- Return the packet timestamp in seconds
timeS :: Packet -> Double
timeS = (/ 1000000) . fromIntegral . time

len :: Packet -> Int
len (_, _, buf) = B.length buf

-- 
-- IPv4 projections
--

has_ipv4 :: Packet -> Bool
has_ipv4 (_, lm, _) = isJust (ipv4 lm)

ipv4_len :: Packet -> Word16
ipv4_len (_, lm, buf) = runGet getWord16be (buf & B.drop (fromJust (ipv4 lm) + 2) & B.fromStrict)

ipv4_flags :: Packet -> Word8
ipv4_flags (_, lm, buf) = (B.index buf (fromJust (ipv4 lm) + 6)) `shiftR` 5

ipv4_offset :: Packet -> Word16
ipv4_offset (_, lm, buf) =
    runGet getWord16be (buf & B.drop (fromJust (ipv4 lm) + 6) & B.fromStrict) .&. 0xE000

ipv4_ttl :: Packet -> Word8
ipv4_ttl (_, lm, buf) = (B.index buf (fromJust (ipv4 lm) + 8))

ipv4_proto :: Packet -> Word8
ipv4_proto (_, lm, buf) = B.index buf (fromJust (ipv4 lm) + 9)

ipv4_src :: Packet -> Word32
ipv4_src (_, lm, buf) = runGet getWord32be (buf & B.drop (fromJust (ipv4 lm) + 12) & B.fromStrict)

ipv4_dst :: Packet -> Word32
ipv4_dst (_, lm, buf) = runGet getWord32be (buf & B.drop (fromJust (ipv4 lm) + 16) & B.fromStrict)

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
-- TCP projections
--

has_tcp :: Packet -> Bool
has_tcp (_, lm, _) = isJust (tcp lm)

tcp_sport :: Packet -> Word16
tcp_sport (_, lm, buf) = runGet getWord16be (buf & B.drop (fromJust (tcp lm) + 0) & B.fromStrict)

tcp_dport :: Packet -> Word16
tcp_dport (_, lm, buf) = runGet getWord16be (buf & B.drop (fromJust (tcp lm) + 2) & B.fromStrict)

tcp_seq :: Packet -> Word32
tcp_seq (_, lm, buf) = runGet getWord32be (buf & B.drop (fromJust (tcp lm) + 4) & B.fromStrict)

tcp_flags :: Packet -> Word16
tcp_flags (_, lm, buf) = runGet getWord16be (buf & B.drop (fromJust (tcp lm) + 12) & B.fromStrict)

set_bit :: Int -> Word16
set_bit n = 0x1 `shiftL` n

tcp_fin :: Word16
tcp_fin = set_bit 0

tcp_syn :: Word16
tcp_syn = set_bit 1

tcp_rst :: Word16
tcp_rst = set_bit 2

tcp_psh :: Word16
tcp_psh = set_bit 3

tcp_ack :: Word16
tcp_ack = set_bit 4

tcp_urg :: Word16
tcp_urg = set_bit 5

-- 
-- UDP projections
--

has_udp :: Packet -> Bool
has_udp (_, lm, _) = isJust (udp lm)

udp_sport :: Packet -> Word16
udp_sport (_, lm, buf) = runGet getWord16be (buf & B.drop (fromJust (udp lm) + 0) & B.fromStrict)

udp_dport :: Packet -> Word16
udp_dport (_, lm, buf) = runGet getWord16be (buf & B.drop (fromJust (udp lm) + 2) & B.fromStrict)

-- 
-- WLAN projections
--

has_wlan :: Packet -> Bool
has_wlan (_, lm, _) = isJust (wlan lm)

wlan_type :: Packet -> Word8
wlan_type (_, lm, buf) = ((B.index buf (fromJust (wlan lm))) `shiftR` 2) .&. 0x3

wlan_subtype :: Packet -> Word8
wlan_subtype (_, lm, buf) = (B.index buf (fromJust (wlan lm))) `shiftR` 4

wlan_tods :: Packet -> Bool
wlan_tods (_, lm, buf) = (B.index buf (fromJust (wlan lm) + 1)) .&. 0x1 /= 0

wlan_fromds :: Packet -> Bool
wlan_fromds (_, lm, buf) = (B.index buf (fromJust (wlan lm) + 1)) .&. 0x2 /= 0

wlan_src :: Packet -> MACAddress
wlan_src (_, lm, buf) = buf & B.drop (10 + fromJust (wlan lm)) & B.take 6 & MAC

wlan_dst :: Packet -> MACAddress
wlan_dst (_, lm, buf) = buf & B.drop (4 + fromJust (wlan lm)) & B.take 6 & MAC

wlan_router :: Packet -> MACAddress
wlan_router (_, lm, buf) = buf & B.drop (16 + fromJust (wlan lm)) & B.take 6 & MAC

