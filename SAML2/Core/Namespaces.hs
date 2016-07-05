-- |
-- Schema Organization and Namespaces
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf saml-core-2.0-os> §1.2
module SAML2.Core.Namespaces 
  ( samlURN
  , SAMLVersion(..)
  ) where

import Data.Monoid ((<>))
import qualified Network.URI as URI

import SAML2.Version

-- |The argument must be a valid URN path (unchecked)
makeURN :: String -> URI.URI
makeURN p = URI.nullURI
  { URI.uriScheme = "urn:"
  , URI.uriPath = p
  }

samlURN :: SAMLVersion -> String -> String -> URI.URI
samlURN v t n = makeURN $ "oasis:names:tc:SAML" <> concatMap (':':) [show v, t, n]
