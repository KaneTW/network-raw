{-# LANGUAGE RecordWildCards, TemplateHaskell #-}
module Network.Raw.IPv4 where

import Control.Lens
import Control.Monad
import Control.Monad.Catch
import Control.Monad.State
import Data.Binary (Get)
import Data.Binary.Bits.Get
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Conduit
import qualified Data.Conduit.Combinators as CC
import Data.Conduit.Lift
import Data.Conduit.Serialization.Binary
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as M
import Data.Word

type IPv4Address = Word32

data IPBody = TCPBody !TCPPacket | UnknownBody !Word8 !ByteString
            deriving (Show, Eq)

-- |Minimum amount of information to reassemble a IP packet.
-- Potentially fragmented, but for now we assume they're not.
data IPv4Packet = IPv4Packet { _ipSrcAddress     :: !IPv4Address
                             , _ipDstAddress     :: !IPv4Address
                             , _ipIdent          :: !Word16
                             , _ipDontFragment   :: !Bool
                             , _ipMoreFragments  :: !Bool
                             , _ipFragmentOffset :: !Word16
                             , _ipBody           :: !IPBody
                             }
                deriving (Show, Eq)

data TCPPacket = TCPPacket { _tcpSrcAddress :: !IPv4Address
                           , _tcpDstAddress :: !IPv4Address
                           , _tcpSrcPort   :: !Word16
                           , _tcpDstPort   :: !Word16
                           , _tcpSeqNumber :: !Word32
                           , _tcpAckNumber :: !Word32
                           , _tcpNs :: !Bool
                           , _tcpCwr :: !Bool
                           , _tcpEce :: !Bool
                           , _tcpUrg :: !Bool
                           , _tcpAck :: !Bool
                           , _tcpPsh :: !Bool
                           , _tcpRst :: !Bool
                           , _tcpSyn :: !Bool
                           , _tcpFin :: !Bool
                           , _tcpWindowSize  :: !Word16
                           , _tcpBody :: !ByteString
                           }
               deriving (Show, Eq)

makeLenses ''IPv4Packet
makeLenses ''TCPPacket

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
toTCPPacket pck = case pck^.ipBody  of 
  TCPBody tcp -> Just tcp
  _ -> Nothing

conduitIPv4 :: MonadThrow m => Conduit ByteString m IPv4Packet
conduitIPv4 = conduitGet getIPv4Packet

conduitTCP :: MonadThrow m => Conduit IPv4Packet m TCPPacket
conduitTCP = CC.concatMap toTCPPacket

data TCPStreamId = TCPStreamId { _streamSrcAddress :: !IPv4Address
                               , _streamDstAddress :: !IPv4Address
                               , _streamSrcPort    :: !Word16
                               , _streamDstPort    :: !Word16
                               }
                 deriving (Show, Eq)

makeLenses ''TCPStreamId

streamOf :: TCPPacket -> TCPStreamId
streamOf TCPPacket{..} = TCPStreamId _tcpSrcAddress _tcpDstAddress _tcpSrcPort _tcpDstPort

data TCPStreamState = TCPStreamState { _streamNextSeq :: Maybe Word32
                                     , _streamPacketQueue :: Map Word32 TCPPacket
                                     }
                    deriving (Show, Eq)

makeLenses ''TCPStreamState

initialStreamState :: TCPStreamState
initialStreamState = TCPStreamState Nothing M.empty

-- This is tricky, because packets can arrive out of order.
conduitTCPStream :: MonadThrow m => TCPStreamId -> Conduit TCPPacket m ByteString
conduitTCPStream stream = CC.filter (\x -> stream == streamOf x) =$= reconstructStream
 where
  reconstructStream = evalStateC initialStreamState $ awaitForever $ \pack -> do
    prev <- get
    case prev^.streamNextSeq of
      Just prevSeq | prevSeq < pack^.tcpSeqNumber -> do -- we're missing a packet, add to queue
                       streamPacketQueue %= M.insert (pack^.tcpSeqNumber) pack
                   | prevSeq > pack^.tcpSeqNumber -> return () -- discard packets where we saw a later packet first
      _ -> do
        streamNextSeq .= Just (pack^.tcpSeqNumber + fromIntegral (BS.length $ pack^.tcpBody))
        yield $ pack^.tcpBody
