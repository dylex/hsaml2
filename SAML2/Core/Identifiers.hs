{-# LANGUAGE TypeSynonymInstances, FlexibleInstances #-}
-- |
-- SAML-Defined Identifiers
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf saml-core-2.0-os> §8
module SAML2.Core.Identifiers where

import SAML2.XML
import qualified SAML2.XML.Pickle as XP
import SAML2.Core.Namespaces

-- |§8.1
data ActionNamespace
  = ActionNamespaceRWEDC -- ^§8.1.1: Read Write Execute Delete Control
  | ActionNamespaceRWEDCNegation -- ^§8.1.2: RWEDC ~RWEDC
  | ActionNamespaceGHPP -- ^§8.1.3: GET HEAD PUT POST
  | ActionNamespaceUNIX -- ^§8.1.4: octal
  deriving (Eq, Enum, Bounded, Show)

instance XP.XmlPickler (PreidentifiedURI ActionNamespace) where
  xpickle = xpSAMLURN "action" f where
    f ActionNamespaceRWEDC          = (SAML10, "rwedc")
    f ActionNamespaceRWEDCNegation  = (SAML10, "rwedc-negation")
    f ActionNamespaceGHPP           = (SAML10, "ghpp")
    f ActionNamespaceUNIX           = (SAML10, "unix")

-- |§8.2
data AttributeNameFormat
  = AttributeNameFormatUnspecified -- ^§8.2.1: Text
  | AttributeNameFormatURI -- ^§8.2.2: URI
  | AttributeNameFormatBasic -- ^§8.2.3: Name
  deriving (Eq, Enum, Bounded, Show)

instance XP.XmlPickler (PreidentifiedURI AttributeNameFormat) where
  xpickle = xpSAMLURN "attrname-format" f where
    f AttributeNameFormatUnspecified = (SAML20, "unspecified")
    f AttributeNameFormatURI         = (SAML20, "uri")
    f AttributeNameFormatBasic       = (SAML20, "basic")

-- |§8.3
data NameIDFormat
  = NameIDFormatUnspecified -- ^§8.3.1: Text
  | NameIDFormatEmail -- ^§8.3.2: rfc2822
  | NameIDFormatX509 -- ^§8.3.3: XML signature
  | NameIDFormatWindows -- ^§8.3.4: Maybe Domain, User
  | NameIDFormatKerberos -- ^§8.3.5: rfc1510
  | NameIDFormatEntity -- ^§8.3.6: SAML endpoint (BaseId and SPProvidedID must be Nothing)
  | NameIDFormatPersistent -- ^§8.3.7: String <= 256 char (NameQualifier same as idp ident/Nothing, SPNameQualifier same as sp ident/Nothing, SPProvidedID alt ident from sp)
  | NameIDFormatTransient -- ^§8.3.8: String <= 256 char
  deriving (Eq, Enum, Bounded, Show)
  
instance XP.XmlPickler (PreidentifiedURI NameIDFormat) where
  xpickle = xpSAMLURN "nameid-format" f where
    f NameIDFormatUnspecified = (SAML11, "unspecified")
    f NameIDFormatEmail       = (SAML11, "emailAddress")
    f NameIDFormatX509        = (SAML11, "X509SubjectName")
    f NameIDFormatWindows     = (SAML11, "WindowsDomainQualifiedName")
    f NameIDFormatKerberos    = (SAML20, "kerberos")
    f NameIDFormatEntity      = (SAML20, "entity")
    f NameIDFormatPersistent  = (SAML20, "persistent")
    f NameIDFormatTransient   = (SAML20, "transient")
