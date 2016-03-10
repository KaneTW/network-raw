{-# LANGUAGE FlexibleInstances, MultiParamTypeClasses #-}
module Network.Raw.Windows where

import Data.Proxy
import Foreign
import Network.Socket
import Network.Socket.IOCtl

-- This is sort of hardcoded. Hacky.
data RcvAll = RcvAllOff | RcvAllOn | RcvAllSocketLevelOnly | RcvAllIpLevelOnly
            deriving (Show, Eq, Enum, Bounded)

rcvAll :: Proxy RcvAll
rcvAll = Proxy

instance Storable RcvAll where
  sizeOf _ = sizeOf (undefined  :: Int)
  alignment _ = alignment (undefined :: Int)
  peek p = toEnum <$> peek (castPtr p)
  poke p = poke (castPtr p) . fromEnum

instance IOControl (Proxy RcvAll) RcvAll where
  ioctlReq _ = 2550136833

mkRcvAllSocket :: HostAddress -- ^ local address to bind to
                  -> IO Socket
mkRcvAllSocket addr = do
  sock <- socket AF_INET Raw defaultProtocol
  bind sock $ SockAddrInet 0 addr
  ioctlsocket_ sock rcvAll RcvAllIpLevelOnly
  return sock
