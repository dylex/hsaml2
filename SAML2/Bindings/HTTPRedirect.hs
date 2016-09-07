{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
-- |
-- HTTP Redirect Binding
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf saml-bindings-2.0-os> §3.4
module SAML2.Bindings.HTTPRedirect 
  ( encodeQuery
  , encodeHeaders
  , decodeURI
  ) where

import qualified Codec.Compression.Zlib.Raw as DEFLATE
import Control.Lens ((^.), (.~))
import Control.Monad (unless)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.Lazy as Base64
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as BSL
import Data.Maybe (fromMaybe, maybeToList)
import Data.Monoid ((<>))
import Data.Proxy (Proxy(..))
import Network.HTTP.Types.Header (ResponseHeaders, hLocation, hCacheControl, hPragma)
import Network.HTTP.Types.URI (Query, renderQuery, urlDecode)
import Network.HTTP.Types.QueryLike (toQuery)
import Network.URI (URI(uriPath), nullURI, uriQuery, parseURIReference)

import SAML2.Lens
import SAML2.XML
import qualified SAML2.XML.Signature as DS
import SAML2.Core.Namespaces
import SAML2.Core.Versioning
import qualified SAML2.Core.Protocols as SAMLP
import SAML2.Bindings.General
import SAML2.Bindings.Internal

data Encoding
  = EncodingDEFLATE
  deriving (Eq, Bounded, Enum, Show)

instance Identifiable URI Encoding where
  identifier = samlURNIdentifier "bindings:URL-Encoding" . f where
    f EncodingDEFLATE = (SAML20, "DEFLATE")

paramSAML :: Bool -> BS.ByteString
paramSAML = protocolParameter

paramRelayState, paramSignature, paramSignatureAlgorithm, paramEncoding :: BS.ByteString
paramRelayState = relayStateParameter
paramSignature = "Signature"
paramSignatureAlgorithm = "SigAlg"
paramEncoding = "SAMLEncoding"

encodeQuery :: SAMLP.SAMLProtocol a => Maybe DS.SigningKey -> a -> IO Query
encodeQuery sk p = case sk of
  Nothing -> return sq
  Just k -> do
    let sq' = sq ++ toQuery [(paramSignatureAlgorithm, show $ identifier $ DS.signingKeySignatureAlgorithm k)]
    sig <- DS.signBase64 k $ renderQuery False sq'
    return $ sq' ++ toQuery [(paramSignature, sig)]
  where
  p' = SAMLP.samlProtocol' . $(fieldLens 'SAMLP.protocolSignature) .~ Nothing $ p
  pv = Base64.encode
    $ DEFLATE.compressWith DEFLATE.defaultCompressParams{ DEFLATE.compressLevel = DEFLATE.bestCompression }
    $ SAMLP.samlProtocolToXML p'
  sq = toQuery $ 
    (paramSAML $ SAMLP.isSAMLResponse p, BSL.toStrict pv)
    : maybeToList ((paramRelayState, ) <$> SAMLP.relayState (p' ^. SAMLP.samlProtocol'))

httpHeaders :: ResponseHeaders
httpHeaders =
  [ (hCacheControl, "no-cache,no-store")
  , (hPragma,       "no cache")
  ]

encodeHeaders :: SAMLP.SAMLProtocol a => Maybe DS.SigningKey -> a -> IO ResponseHeaders
encodeHeaders sk p = do
  q <- encodeQuery sk p
  return $
    (hLocation, BSC.pack $ show (fromMaybe nullURI d){ uriQuery = BSC.unpack $ renderQuery True q })
    : httpHeaders
  where
  d = SAMLP.protocolDestination $ p ^. SAMLP.samlProtocol'

decodeURI :: forall a . SAMLP.SAMLProtocol a => DS.PublicKeys -> URI -> IO a
decodeURI pk ru = do
  pq <- maybe (fail "SAML parameter missing") return $ lookupProtocolParameter (Proxy :: Proxy a) ql
  pd <- case enc of
    Identified EncodingDEFLATE ->
      return $ DEFLATE.decompress $ Base64.decodeLenient $ BSL.fromStrict $ fst pq
    _ -> fail $ "Unsupported HTTP redirect encoding: " ++ show enc
  p <- either fail return $ SAMLP.samlXMLToProtocol pd
  case ql paramSignatureAlgorithm of
    Just (sav, sas) -> do
      sigres $ DS.verifyBase64 pk (reidentify $ puri sav)
        (snd pq <> foldMap (BSC.cons '&' . snd) rsq <> BSC.cons '&' sas)
        (foldMap fst $ ql paramSignature)
      unless (SAMLP.protocolDestination (p ^. SAMLP.samlProtocol') == Just ru{ uriQuery = "" }) $
        fail "Destination incorrect"
    Nothing -> return ()
  return $ SAMLP.samlProtocol' . $(fieldLens 'SAMLP.relayState) .~ (fst <$> rsq) $ p
  where
  qs = BSC.pack $ uriQuery ru
  pqp s = (urlDecode True k, (maybe BSC.empty (urlDecode True . snd) $ BS.uncons v, s)) where
    (k, v) = BSC.break ('=' ==) s
  q = map pqp $ BSC.splitWith (`elem` ['&',';']) $ case BSC.uncons qs of
    Just ('?', qs') -> qs'
    _ -> qs
  ql v = lookup v q
  puri bs = fromMaybe nullURI{ uriPath = s } $ parseURIReference s where s = BSC.unpack bs
  enc = maybe (Identified EncodingDEFLATE) reidentify $ fmap (puri . fst) $ ql paramEncoding
  rsq = ql paramRelayState
  sigres (Just True) = return ()
  sigres (Just False) = fail "Signature verification failed"
  sigres Nothing = fail "Could not verify signature"

