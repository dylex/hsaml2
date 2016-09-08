-- |
-- Assertions and Protocols for the OASIS Security Assertion Markup Language (SAML) V2.0
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf saml-core-2.0-os>
module SAML2.Core
  ( -- * §1
    samlURN
  , XString
  , AnyURI
  , DateTime
  , ID
  , NCName
    -- * §2
  , SAML.ns
  , BaseID(..)
  , NameID(..)
  , simpleNameID
  , EncryptedNameID
  , Identifier(..)
  , EncryptedID
  , EncryptedElement(..)
  , PossiblyEncrypted(..)
  , AssertionRef(..)
  , Issuer(..)
  , AssertionIDRef(..)
  , Assertion(..)
  , AssertionStatement(..)
  , EncryptedAssertion
  , Subject(..)
  , noSubject
  , SubjectConfirmation(..)
  , SubjectConfirmationData(..)
  , Conditions(..)
  , Condition(..)
  , Audience(..)
  , Advice
  , AdviceElement(..)
  , Statement(..)
  , AuthnStatement(..)
  , SubjectLocality(..)
  , AuthnContext(..)
  , AuthnContextDecl(..)
  , AttributeStatement(..)
  , Attribute(..)
  , EncryptedAttribute
  , AuthzDecisionStatement(..)
  , DecisionType(..)
  , Action(..)
  , Evidence(..)
    -- * §3
  , nsP
  , ProtocolType(..)
  , RequestAbstractType(..)
  , StatusResponseType(..)
  , Status(..)
  , StatusCode(..)
  , StatusCode1(..)
  , StatusCode2(..)
  , successStatus
  , AssertionIDRequest(..)
  , SubjectQueryAbstractType(..)
  , AuthnQuery(..)
  , RequestedAuthnContext(..)
  , AuthnContextRefs(..)
  , AuthnContextComparisonType(..)
  , AttributeQuery(..)
  , AuthzDecisionQuery(..)
  , Response(..)
  , AuthnRequest(..)
  , AssertionConsumerService(..)
  , NameIDPolicy(..)
  , Scoping(..)
  , IDPList(..)
  , IDPEntry(..)
  , ArtifactResolve(..)
  , ArtifactResponse(..)
  , ManageNameIDRequest(..)
  , NewID(..)
  , NewEncryptedID
  , ManageNameIDResponse(..)
  , LogoutRequest(..)
  , LogoutResponse(..)
  , LogoutReason(..)
  , NameIDMappingRequest(..)
  , NameIDMappingResponse(..)
  , AnyRequest(..)
  , AnyResponse(..)
  , AnyProtocol(..)
    -- * §4
  , SAMLVersion(..)
  , samlVersion
    -- * §8
  , ActionNamespace(..)
  , AttributeNameFormat(..)
  , NameIDFormat(..)
  , Consent(..)
  ) where

import SAML2.XML.Types
import SAML2.Core.Namespaces
import SAML2.Core.Datatypes
import SAML2.Core.Assertions as SAML
import SAML2.Core.Protocols as SAMLP
import SAML2.Core.Versioning
import SAML2.Core.Identifiers

nsP :: Namespace
nsP = SAMLP.ns
