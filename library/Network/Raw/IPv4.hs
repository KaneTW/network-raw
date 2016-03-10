-- |This package is meant to be imported qualified
module Network.Raw.IPv4 where

import Control.Monad
import Data.Binary (Get)
import Data.Binary.Bits.Get
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word

type IPv4Address = Word32

-- |Minimum amount of information to reassemble a IP packet.
-- Potentially fragmented.
data RawIPv4Packet = RawIPv4Packet { ipSrcAddress     :: !IPv4Address
                                   , ipDstAddress     :: !IPv4Address
                                   , ipIdent          :: !Word16
                                   , ipDontFragment   :: !Bool
                                   , ipMoreFragments  :: !Bool
                                   , ipFragmentOffset :: !Word16
                                   , ipProtocol       :: !Word8
                                   , ipBody           :: !ByteString
                                   }
                   deriving (Show, Eq)

getRawIPv4Packet :: Get RawIPv4Packet
getRawIPv4Packet = runBitGet $ do
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

  let remainingHeader = (fromIntegral headerLength) - 5
  _ <- getByteString remainingHeader
  
  let bodySize = (fromIntegral totalLength) - 4 * (fromIntegral headerLength)
  body <- getByteString bodySize
  
  return $ RawIPv4Packet src dst ident df mf frags proto body

  
