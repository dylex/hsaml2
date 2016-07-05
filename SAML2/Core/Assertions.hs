-- |
-- SAML Assertions
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf saml-core-2.0-os> §2
module SAML2.Core.Assertions where

import qualified SAML2.XML as XML
import qualified SAML2.XML.Encryption as XEnc
import qualified SAML2.XML.Signature as DS
import SAML2.Version
import SAML2.Core.Identifiers
import SAML2.Profiles.ConfirmationMethod

-- |§2.2.1
data BaseID id = BaseID
  { baseNameQualifier :: Maybe XML.String
  , baseSPNameQualifier :: Maybe XML.String
  , baseID :: !id
  }

-- |§2.2.3
data NameID = NameID
  { nameBaseID :: BaseID XML.String
  , nameIDFormat :: NameIDFormat
  , nameSPProvidedID :: Maybe XML.String
  }

data Identifier
  = IdentifierName NameID
  | IdentifierBase (BaseID XML.Nodes)

data AssertionRef
  = AssertionIDRef XML.ID -- ^§2.3.1
  | AssertionURIRef XML.AnyURI -- ^§2.3.2
  | AssertionRef (XEnc.PossiblyEncrypted Assertion)

-- |§2.3.3
data AssertionStatement
  = AssertionStatement Statement
  | AssertionAuthnStatement AuthnStatement
  | AssertionAuthzDecisionStatement AuthzDecisionStatement
  | AssertionAttributeStatement AttributeStatement

data Assertion = Assertion
  { assertionVersion :: SAMLVersion
  , assertionID :: XML.ID
  , assertionIssueInstant :: XML.DateTime
  , assertionIssuer :: NameID -- ^§2.2.5
  , assertionSignature :: Maybe DS.Signature
  , assertionSubject :: Subject -- ^use 'noSubject' to omit
  , assertionConditions :: Maybe Conditions
  , assertionAdvice :: Maybe Advice
  , assertionStatement :: [AssertionStatement]
  }

-- |§2.3.4
type EncryptedAssertion = XEnc.EncryptedElement Assertion

-- |§2.4.1
data Subject = Subject
  { subjectIdentifier :: Maybe (XEnc.PossiblyEncrypted Identifier)
  , subjectConfirmation :: [SubjectConfirmation]
  }

noSubject :: Subject
noSubject = Subject Nothing []

-- |§2.4.1.1
data SubjectConfirmation = SubjectConfirmation
  { subjectConfirmationMethod :: ConfirmationMethod
  , subjectConfirmationIdentifier :: Maybe (XEnc.PossiblyEncrypted Identifier)
  , subjectConfirmationData :: SubjectConfirmationData
  }

-- |§2.4.1.2
data SubjectConfirmationData = SubjectConfirmationData
  { subjectConfirmationNotBefore
  , subjectConfirmationNotOnOrAfter :: Maybe XML.DateTime
  , subjectConfirmationRecipient :: Maybe XML.AnyURI
  , subjectConfirmationInResponseTo :: Maybe XML.ID
  , subjectConfirmationAddress :: XML.IP
  , subjectConfirmationXML :: XML.Nodes
  }

-- |§2.5.1
data Conditions = Conditions
  { conditionsNotBefore
  , conditionsNotOnOrAfter :: Maybe XML.DateTime
  , conditions :: [ConditionElement]
  , conditionsOneTimeUse :: Bool
  , conditionsProxyRestriction :: Maybe ProxyRestriction
  }
data ConditionElement
  = ConditionAudienceRestriction (XML.List1 Audience) -- ^§2.5.1.4
  | Condition XML.Node -- ^§2.5.1.3

-- |§2.5.1.4
newtype Audience = Audience XML.AnyURI

-- |§2.5.1.6
data ProxyRestriction = ProxyRestriction
  { proxyRestrictionCount :: Maybe Word
  , proxyRestrictionAudience :: [Audience]
  }

-- |§2.6.1
type Advice = [AdviceElement]
data AdviceElement
  = AdviceAssertion AssertionRef
  | Advice XML.Node

-- |§2.7.1
data Statement
  = StatementAuthn AuthnStatement
  | StatementAttributute AttributeStatement
  | StatementAuthzDecision AuthzDecisionStatement
  | Statement XML.Node

-- |§2.7.2
data AuthnStatement = AuthnStatement
  { authnStatementInstant :: XML.DateTime
  , authnStatementSessionIndex :: Maybe XML.String
  , authnStatementSessionNotOnOrAfter :: Maybe XML.DateTime
  , authnStatementSubjectLocality :: Maybe SubjectLocality
  , authnStatementContext :: AuthnContext
  }

-- |§2.7.2.1
data SubjectLocality = SubjectLocality
  { subjectLocalityAddress :: Maybe XML.IP
  , subjectLocalityDNSName :: Maybe XML.String
  }

-- |§2.7.2.2
data AuthnContext = AuthnContext
  { authnContextClassRef :: Maybe XML.AnyURI
  , authnContextDecl :: Maybe AuthnContextDecl
  , authnContextAuthenticatingAuthority :: [XML.AnyURI]
  }

data AuthnContextDecl
  = AuthnContextDecl XML.Node
  | AuthnContextDeclRef XML.AnyURI

-- |§2.7.3
newtype AttributeStatement = AttributeStatement (XML.List1 (XEnc.PossiblyEncrypted Attribute))

-- |§2.7.3.1
data Attribute = Attribute
  { attributeName :: XML.String
  , attributeNameFormat :: AttributeNameFormat
  , attributeFriendlyName :: Maybe XML.String
  , attributeXML :: XML.Nodes -- attributes
  , attributeValues :: [AttributeValue]
  }

-- |§2.7.3.1.1
newtype AttributeValue = AttributeValue XML.Nodes

-- |§2.7.3.2
type EncryptedAttribute = XEnc.EncryptedElement Attribute

-- |§2.7.4
data AuthzDecisionStatement = AuthzDecisionStatement
  { authzDecisionStatementResource :: XML.AnyURI
  , authzDecisionStatementDecision :: DecisionType
  , authzDecisionStatementAction :: XML.List1 Action
  , authzDecisionStatementEvidence :: Maybe Evidence
  }

-- |§2.7.4.1
data DecisionType
  = DecisionTypePermit
  | DecisionTypeDeny
  | DecisionTypeIndeterminate

-- |§2.7.4.2
data Action = Action
  { actionNamespace :: ActionNamespace
  , action :: XML.String
  }

-- |§2.7.4.3
type Evidence = AssertionRef
