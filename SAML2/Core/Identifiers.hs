-- |
-- SAML-Defined Identifiers
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf saml-core-2.0-os> §8
module SAML2.Core.Identifiers where

import qualified SAML2.XML as XML
import SAML2.Core.Namespaces

-- |§8.1
data ActionNamespace
  = ActionNamespaceRWEDC -- ^§8.1.1: Read Write Execute Delete Control
  | ActionNamespaceRWEDCNegation -- ^§8.1.2: RWEDC ~RWEDC
  | ActionNamespaceGHPP -- ^§8.1.3: GET HEAD PUT POST
  | ActionNamespaceUNIX -- ^§8.1.4: octal

-- |§8.2
data AttributeNameFormat
  = AttributeNameFormatUnspecified -- ^§8.2.1: Text
  | AttributeNameFormatURI -- ^§8.2.2: URI
  | AttributeNameFormatBasic -- ^§8.2.3: Name
  | AttributeNameFormat XML.AnyURI

attributeNameFormatURN :: AttributeNameFormat -> XML.AnyURI
attributeNameFormatURN AttributeNameFormatUnspecified = samlURN SAML20 "attrname-format" "unspecified"
attributeNameFormatURN AttributeNameFormatURI         = samlURN SAML20 "attrname-format" "uri"
attributeNameFormatURN AttributeNameFormatBasic       = samlURN SAML20 "attrname-format" "basic"
attributeNameFormatURN (AttributeNameFormat u) = u

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
  | NameIDFormat XML.AnyURI
  
nameIDFormatURN :: NameIDFormat -> XML.AnyURI
nameIDFormatURN NameIDFormatUnspecified = samlURN SAML11 "nameid-format" "unspecified"
nameIDFormatURN NameIDFormatEmail       = samlURN SAML11 "nameid-format" "emailAddress"
nameIDFormatURN NameIDFormatX509        = samlURN SAML11 "nameid-format" "X509SubjectName"
nameIDFormatURN NameIDFormatWindows     = samlURN SAML11 "nameid-format" "WindowsDomainQualifiedName"
nameIDFormatURN NameIDFormatKerberos    = samlURN SAML20 "nameid-format" "kerberos"
nameIDFormatURN NameIDFormatEntity      = samlURN SAML20 "nameid-format" "entity"
nameIDFormatURN NameIDFormatPersistent  = samlURN SAML20 "nameid-format" "persistent"
nameIDFormatURN NameIDFormatTransient   = samlURN SAML20 "nameid-format" "transient"
nameIDFormatURN (NameIDFormat u) = u

