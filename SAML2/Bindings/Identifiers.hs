{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
-- |
-- Protocol Bindings identifiers
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf saml-bindings-2.0-os> §3.X.1
module SAML2.Bindings.Identifiers where

import SAML2.XML
import SAML2.Core.Namespaces
import SAML2.Core.Versioning

data Binding
  = BindingSOAP -- ^§3.2
  | BindingPAOS -- ^§3.3
  | BindingHTTPRedirect -- ^§3.4
  | BindingHTTPPOST -- ^§3.5
  | BindingHTTPArtifact -- ^§3.6
  | BindingURI -- ^§3.7
  deriving (Eq, Bounded, Enum, Show)

instance Identifiable URI Binding where
  identifier = samlURNIdentifier "bindings" . f where
    f BindingSOAP         = (SAML20, "SOAP")
    f BindingPAOS         = (SAML20, "PAOS")
    f BindingHTTPRedirect = (SAML20, "HTTP-Redirect")
    f BindingHTTPPOST     = (SAML20, "HTTP-POST")
    f BindingHTTPArtifact = (SAML20, "HTTP-Artifact")
    f BindingURI          = (SAML20, "URI")
