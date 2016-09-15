{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}
-- |
-- HTTP POST Binding
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf saml-bindings-2.0-os> §3.5
module SAML2.Bindings.HTTPPOST
  ( encodeValue
  , encodeForm
  , decodeValue
  , decodeForm
  ) where

import Control.Lens ((^.), (.~))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Lazy as BSL
import Data.Maybe (maybeToList)
import Data.Proxy (Proxy(..))

import SAML2.XML
import SAML2.Lens
import qualified SAML2.Core.Protocols as SAMLP
import SAML2.Core.Signature
import SAML2.Bindings.General
import SAML2.Bindings.Internal

encodeValue :: SAMLP.SAMLProtocol a => a -> BS.ByteString
encodeValue = Base64.encode . BSL.toStrict . samlToXML

encodeForm :: SAMLP.SAMLProtocol a => a -> [(BS.ByteString, BS.ByteString)]
encodeForm p =
  (protocolParameter (SAMLP.isSAMLResponse p), encodeValue p)
  : maybeToList ((relayStateParameter, ) <$> SAMLP.relayState (p ^. SAMLP.samlProtocol'))

decodeValue :: SAMLP.SAMLProtocol a => Bool -> BS.ByteString -> IO a
decodeValue verf v = do
  if verf
    then verifySAMLProtocol b
    else either fail return $ xmlToSAML b
  where b = BSL.fromStrict $ Base64.decodeLenient v

decodeForm :: forall a . (SAMLP.SAMLProtocol a) => Bool -> (BS.ByteString -> Maybe BS.ByteString) -> IO a
decodeForm verf f = do
  p <- decodeValue verf =<< maybe (fail "SAML parameter missing") return (lookupProtocolParameter (Proxy :: Proxy a) f)
  return $ SAMLP.samlProtocol' . $(fieldLens 'SAMLP.relayState) .~ (f relayStateParameter) $ p
