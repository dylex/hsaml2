{-# LANGUAGE FlexibleContexts #-}
-- |
-- Schema Organization and Namespaces
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf saml-core-2.0-os> §1.2
module SAML2.Core.Namespaces 
  ( samlURN
  , samlURNIdentifier
  ) where

import Data.Monoid ((<>))
import Network.URI (URI(..))

import SAML2.Core.Versioning

samlURN :: SAMLVersion -> [String] -> URI
samlURN v l = URI
  { uriScheme = "urn:"
  , uriAuthority = Nothing
  , uriPath = "oasis:names:tc:SAML" <> concatMap (':':) (show v : l)
  , uriQuery = ""
  , uriFragment = ""
  }

samlURNIdentifier :: String -> (SAMLVersion, String) -> URI
samlURNIdentifier t (v, n) = samlURN v [t, n]

-- samlURNIdentifier :: String -> (a -> (SAMLVersion, String)) -> (a -> samlURN)
-- samlURNIdentifier = (.) . uncurry . samlURNIdentifier

-- xpSAMLURNIdentifier :: Identifiable URI a => String -> XP.PU a
-- xpSAMLURNIdentifier = xpIdentifier XS.xpAnyURI
