{-# LANGUAGE ViewPatterns #-}
-- |
-- Schema Organization and Namespaces
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf saml-core-2.0-os> §1.2
module SAML2.Core.Namespaces 
  ( SAMLVersion(..)
  , samlURN
  , xpSAMLURN
  ) where

import Data.Monoid ((<>))
import Network.URI (URI(..))

import SAML2.Version
import SAML2.XML
import qualified SAML2.XML.Pickle as XP
import SAML2.Core.Datatypes ()

samlURN :: SAMLVersion -> [String] -> URI
samlURN v l = URI
  { uriScheme = "urn:"
  , uriAuthority = Nothing
  , uriPath = "oasis:names:tc:SAML" <> concatMap (':':) (show v : l)
  , uriQuery = ""
  , uriFragment = ""
  }

xpSAMLURN :: (Enum a, Bounded a) => String -> (a -> (SAMLVersion, String)) -> XP.PU (PreidentifiedURI a)
xpSAMLURN t g = xpPreidentifiedURI (\a -> let (v, n) = g a in samlURN v [t, n])

-- nsProtocol :: Namespace
-- nsProtocol = mkNamespace "samlp" $ samlURN SAML20 ["protocol"]
