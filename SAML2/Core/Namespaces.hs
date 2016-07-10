{-# LANGUAGE ViewPatterns #-}
-- |
-- Schema Organization and Namespaces
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf saml-core-2.0-os> §1.2
module SAML2.Core.Namespaces 
  ( samlURN
  , xpEnumSAMLURN
  , xpPreidentifiedSAMLURN
  ) where

import Data.Monoid ((<>))
import Network.URI (URI(..))

import SAML2.Core.Versioning
import SAML2.XML
import qualified SAML2.XML.Pickle as XP
import qualified SAML2.XML.Schema as XS

samlURN :: SAMLVersion -> [String] -> URI
samlURN v l = URI
  { uriScheme = "urn:"
  , uriAuthority = Nothing
  , uriPath = "oasis:names:tc:SAML" <> concatMap (':':) (show v : l)
  , uriQuery = ""
  , uriFragment = ""
  }

xpEnumSAMLURN :: (Enum a, Bounded a) => String -> (a -> (SAMLVersion, String)) -> XP.PU a
xpEnumSAMLURN t g = xpEnum XS.xpAnyURI t (\a -> let (v, n) = g a in samlURN v [t, n])

xpPreidentifiedSAMLURN :: (Enum a, Bounded a) => String -> (a -> (SAMLVersion, String)) -> XP.PU (PreidentifiedURI a)
xpPreidentifiedSAMLURN t g = xpPreidentifiedURI (\a -> let (v, n) = g a in samlURN v [t, n])

-- nsProtocol :: Namespace
-- nsProtocol = mkNamespace "samlp" $ samlURN SAML20 ["protocol"]
