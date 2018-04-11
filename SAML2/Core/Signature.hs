{-# LANGUAGE ScopedTypeVariables #-}
-- |
-- SAML and XML Signature Syntax and Processing
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf saml-core-2.0-os> §5
module SAML2.Core.Signature
  ( signSAMLProtocol
  , verifySAMLProtocol
  , verifySAMLProtocol'
  ) where

import Control.Exception
import Control.Lens ((^.), (.~))
import Control.Monad (unless)
import qualified Data.ByteString.Lazy as BSL
import Data.List.NonEmpty (NonEmpty((:|)))
import Network.URI (URI(uriFragment), nullURI)
import Text.XML.HXT.DOM.TypeDefs

import SAML2.XML
import qualified SAML2.XML.Canonical as C14N
import qualified SAML2.XML.Signature as DS
import qualified SAML2.Core.Protocols as SAMLP

signSAMLProtocol :: SAMLP.SAMLProtocol a => DS.SigningKey -> a -> IO a
signSAMLProtocol sk m = do
  r <- DS.generateReference DS.Reference
    { DS.referenceId = Nothing
    , DS.referenceURI = Just nullURI{ uriFragment = '#':SAMLP.protocolID p }
    , DS.referenceType = Nothing
    , DS.referenceTransforms = Just $ DS.Transforms
      $  DS.simpleTransform DS.TransformEnvelopedSignature
      :| DS.simpleTransform (DS.TransformCanonicalization $ C14N.CanonicalXMLExcl10 False)
      : []
    , DS.referenceDigestMethod = DS.simpleDigest DS.DigestSHA1
    , DS.referenceDigestValue = error "signSAMLProtocol: referenceDigestValue"
    } $ samlToDoc m
  s' <- DS.generateSignature sk $ maybe DS.SignedInfo
    { DS.signedInfoId = Nothing
    , DS.signedInfoCanonicalizationMethod = DS.simpleCanonicalization $ C14N.CanonicalXMLExcl10 False
    , DS.signedInfoSignatureMethod = DS.SignatureMethod
      { DS.signatureMethodAlgorithm = Identified $ DS.signingKeySignatureAlgorithm sk
      , DS.signatureMethodHMACOutputLength = Nothing
      , DS.signatureMethod = []
      }
    , DS.signedInfoReference = r :| []
    } DS.signatureSignedInfo $ SAMLP.protocolSignature p
  return $ DS.signature' .~ Just s' $ m
  where
  p = m ^. SAMLP.samlProtocol'

verifySAMLProtocol :: SAMLP.SAMLProtocol a => BSL.ByteString -> IO a
verifySAMLProtocol b = do
  x <- maybe (fail "invalid XML") return $ xmlToDoc b
  m <- either fail return $ docToSAML x
  v <- DS.verifySignature mempty (DS.signedID m) x
  unless (or v) $ fail "verifySAMLProtocol: invalid or missing signature"
  return m

-- | A variant of 'verifySAMLProtocol' that is more symmetric to 'signSAMLProtocol'.  The reason it
-- takes an 'XmlTree' and not an @a@ is that signature verification needs both.
--
-- TODO: Should this replace 'verifySAMLProtocol'?
verifySAMLProtocol' :: SAMLP.SAMLProtocol a => DS.PublicKeys -> XmlTree -> IO a
verifySAMLProtocol' pubkeys x = do
  m <- either fail return $ docToSAML x
  v :: Either SomeException (Maybe Bool) <- try $ DS.verifySignature pubkeys (DS.signedID m) x
  case v of
    Left e             -> fail $ "signature verification failed: " ++ show e
    Right Nothing      -> fail "signature verification failed: no matching key/alg pair."
    Right (Just False) -> fail "signature verification failed: verification failed."
    Right (Just True)  -> pure m
