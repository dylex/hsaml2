{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TupleSections #-}
-- |
-- HTTP Redirect Binding
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf saml-bindings-2.0-os> §3.4
module SAML2.Bindings.HTTPRedirect where

import qualified Data.ByteString.Base64.Lazy as Base64
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as BSL
import Data.Maybe (catMaybes)
import Control.Lens.Lens ((<<.~))
import qualified Codec.Compression.Zlib.Raw as DEFLATE
import Network.HTTP.Types.URI (Query)
import Network.HTTP.Types.QueryLike (toQuery)

import SAML2.Lens
import SAML2.XML
import qualified SAML2.XML.Signature as DS
import SAML2.Core.Namespaces
import SAML2.Core.Versioning
import qualified SAML2.Core.Protocols as SAMLP
import SAML2.Bindings.General

data Encoding
  = EncodingDEFLATE
  deriving (Eq, Bounded, Enum, Show)

instance Identifiable URI Encoding where
  identifier = samlURNIdentifier "bindings:URL-Encoding" . f where
    f EncodingDEFLATE = (SAML20, "DEFLATE")

encode :: SAMLP.SAMLProtocol a => a -> Maybe RelayState -> Query
encode p rs = sq where
  (ps, p') = (SAMLP.samlProtocol' . $(fieldLens 'SAMLP.protocolSignature) <<.~ Nothing) p
  pv = Base64.encode
    $ DEFLATE.compressWith DEFLATE.defaultCompressParams{ DEFLATE.compressLevel = DEFLATE.bestCompression }
    $ SAMLP.samlProtocolXML p'
  sq = toQuery $ 
    ( if SAMLP.isSAMLResponse p then "SAMLResponse" else "SAMLRequest", BSL.toStrict pv)
    : catMaybes
    [ ("RelayState", ) <$> rs
    , ("SigAlg", ) . BSC.pack . show . unidentify . DS.signatureMethodAlgorithm . DS.signedInfoSignatureMethod . DS.signatureSignedInfo <$> ps
    ]
