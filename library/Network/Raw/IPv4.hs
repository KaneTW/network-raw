-- |This package is meant to be imported qualified
module Network.Raw.IPv4 where

import Control.Monad
import Control.Monad.Catch
import Data.Binary (Get)
import Data.Binary.Bits.Get
import Data.ByteString (ByteString)
import Data.Conduit
import Data.Conduit.Serialization.Binary
--import qualified Data.ByteString as BS
import Data.Word

type IPv4Address = Word32

-- |Minimum amount of information to reassemble a IP packet.
-- Potentially fragmented.
data IPv4Packet = IPv4Packet { ipSrcAddress     :: !IPv4Address
                             , ipDstAddress     :: !IPv4Address
                             , ipIdent          :: !Word16
                             , ipDontFragment   :: !Bool
                             , ipMoreFragments  :: !Bool
                             , ipFragmentOffset :: !Word16
                             , ipBody           :: !IPBody
                             }
                deriving (Show, Eq)

data TCPPacket = TCPPacket { tcpSrcAddress :: !IPv4Address
                           , tcpDstAddress :: !IPv4Address
                           , tcpSrcPort   :: !Word16
                           , tcpDstPort   :: !Word16
                           , tcpSeqNumber :: !Word32
                           , tcpAckNumber :: !Word32
                           , tcpNs :: !Bool
                           , tcpCwr :: !Bool
                           , tcpEce :: !Bool
                           , tcpUrg :: !Bool
                           , tcpAck :: !Bool
                           , tcpPsh :: !Bool
                           , tcpRst :: !Bool
                           , tcpSyn :: !Bool
                           , tcpFin :: !Bool
                           , tcpWindowSize  :: !Word16
                           , tcpBody :: !ByteString
                           }
               deriving (Show, Eq)

data IPBody = TCPBody !TCPPacket | UnknownBody !Word8 !ByteString
            deriving (Show, Eq)

getIPv4Packet :: Get IPv4Packet
getIPv4Packet = runBitGet $ do
  version <- getWord8 4
  when (version /= 4) $ fail "Incorrect IP version"
  
  headerLength <- getWord8 4
  when (headerLength < 5) $ fail "Incorrect IHL"
  
  _ <- getWord8 6 -- DSCP
  _ <- getWord8 2 -- ECN
  totalLength <- getWord16be 16
  ident <- getWord16be 16
  _ <- getBool -- Reserved bit
  df <- getBool
  mf <- getBool
  frags <- getWord16be 13
  _ <- getWord8 8 -- TTL
  proto <- getWord8 8
  _ <- getWord16be 16 -- Checksum
  src <- getWord32be 32
  dst <- getWord32be 32

  let remainingHeader = 4 * ((fromIntegral headerLength) - 5)
  _ <- getByteString remainingHeader
  
  let bodySize = (fromIntegral totalLength) - 4 * (fromIntegral headerLength)
  
  if proto == 6 then do
    tcp <- getTCPPacket src dst bodySize
    return $ IPv4Packet src dst ident df mf frags (TCPBody tcp)
  else do
    body <- getByteString bodySize
    return $ IPv4Packet src dst ident df mf frags (UnknownBody proto body)

  where
    getTCPPacket srcAddr dstAddr ipBodySize = do
      srcPort <- getWord16be 16
      dstPort <- getWord16be 16
      seqNumber <- getWord32be 32
      ackNumber <- getWord32be 32
      dataOffset <- getWord8 4
      when (dataOffset < 5) $ fail "Incorrect data offset"

      _ <- getWord8 3 -- reserved
      ns <- getBool
      cwr <- getBool
      ece <- getBool
      urg <- getBool
      ack <- getBool
      psh <- getBool
      rst <- getBool
      syn <- getBool
      fin <- getBool
      window <- getWord16be 16
      _ <- getWord16be 16 -- checksum
      _ <- getWord16be 16 -- urgent pointer

      let remainingHeader = 4 * ((fromIntegral dataOffset) - 5)
      _ <- getByteString remainingHeader

      let bodySize = ipBodySize - 4 * (fromIntegral dataOffset) 
      body <- getByteString bodySize
      return $ TCPPacket srcAddr dstAddr srcPort dstPort seqNumber ackNumber ns cwr ece urg ack psh rst syn fin window body

toTCPPacket :: IPv4Packet -> Maybe TCPPacket
toTCPPacket pck = case ipBody pck of 
  TCPBody tcp -> Just tcp
  _ -> Nothing

conduitIPv4 :: MonadThrow m => Conduit ByteString m IPv4Packet
conduitIPv4 = conduitGet getIPv4Packet
