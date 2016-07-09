{-# LANGUAGE TypeSynonymInstances, FlexibleInstances, QuasiQuotes #-}
-- |
-- SAML Assertions
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf saml-core-2.0-os> §2
module SAML2.Core.Assertions where

import SAML2.XML
import qualified SAML2.XML.Pickle as XP
import qualified SAML2.XML.Schema as XS
import qualified SAML2.XML.Encryption as XEnc
import qualified SAML2.XML.Signature as DS
import SAML2.Version
import SAML2.Core.Namespaces
import SAML2.Core.Identifiers
import SAML2.Profiles.ConfirmationMethod

ns :: Namespace
ns = mkNamespace "saml" $ samlURN SAML20 ["assertion"]

nsName :: XString -> QName
nsName = mkNName ns

-- |§2.2.1
data BaseID id = BaseID
  { baseNameQualifier :: Maybe XString
  , baseSPNameQualifier :: Maybe XString
  , baseID :: !id
  } deriving (Eq, Show)

xpBaseID :: XP.PU id -> XP.PU (BaseID id)
xpBaseID idp = [XP.biCase|((n, s), i) <-> BaseID n s i|]
  XP.>$<  (XP.xpOption (XP.xpAttr "NameQualifier"   XS.xpString)
    XP.>*< XP.xpOption (XP.xpAttr "SPNameQualifier" XS.xpString)
    XP.>*< idp)

-- |§2.2.3
data NameID = NameID
  { nameBaseID :: BaseID XString
  , nameIDFormat :: PreidentifiedURI NameIDFormat
  , nameSPProvidedID :: Maybe XString
  } deriving (Eq, Show)

instance XP.XmlPickler NameID where
  xpickle = XP.xpElemQN (nsName "NameID") $
    [XP.biCase|((f, p), b) <-> NameID b f p|]
    XP.>$<  (XP.xpDefault (Preidentified NameIDFormatUnspecified) (XP.xpAttr "Format" XP.xpickle)
      XP.>*< XP.xpOption (XP.xpAttr "SPProvidedID" XS.xpString)
      XP.>*< xpBaseID XS.xpString)

data Identifier
  = IdentifierName NameID
  | IdentifierBase (BaseID Nodes)
  deriving (Eq, Show)

instance XP.XmlPickler Identifier where
  xpickle = [XP.biCase|
      Left n <-> IdentifierName n
      Right b <-> IdentifierBase b |]
    XP.>$< (XP.xpickle XP.>|< XP.xpElemQN (nsName "BaseID") (xpBaseID XP.xpTrees))

-- |§2.2.4
type EncryptedID = EncryptedElement Identifier

instance XP.XmlPickler EncryptedID where
  xpickle = XP.xpElemQN (nsName "EncryptedID") xpEncryptedElement

data EncryptedElement a = EncryptedElement
  { encryptedData :: XEnc.EncryptedData
  , encryptedKey :: [XEnc.EncryptedKey]
  }

xpEncryptedElement :: XP.PU (EncryptedElement a)
xpEncryptedElement = [XP.biCase|(d, k) <-> EncryptedElement d k|]
  XP.>$< (XP.xpickle
    XP.>*< XP.xpList XP.xpickle)

data PossiblyEncrypted a
  = NotEncrypted !a
  | SoEncrypted (EncryptedElement a)

xpPossiblyEncrypted :: XP.PU a -> XP.PU (EncryptedElement a) -> XP.PU (PossiblyEncrypted a)
xpPossiblyEncrypted u e = [XP.biCase|
    Left a <-> NotEncrypted a
    Right a <-> SoEncrypted a |]
  XP.>$< (u XP.>|< e)

data AssertionRef
  = AssertionIDRef ID -- ^§2.3.1
  | AssertionURIRef AnyURI -- ^§2.3.2
  | AssertionRef (PossiblyEncrypted Assertion)

-- |§2.3.3
data AssertionStatement
  = AssertionStatement Statement
  | AssertionAuthnStatement AuthnStatement
  | AssertionAuthzDecisionStatement AuthzDecisionStatement
  | AssertionAttributeStatement AttributeStatement

data Assertion = Assertion
  { assertionVersion :: SAMLVersion
  , assertionID :: ID
  , assertionIssueInstant :: DateTime
  , assertionIssuer :: NameID -- ^§2.2.5
  , assertionSignature :: Maybe DS.Signature
  , assertionSubject :: Subject -- ^use 'noSubject' to omit
  , assertionConditions :: Maybe Conditions
  , assertionAdvice :: Maybe Advice
  , assertionStatement :: [AssertionStatement]
  }

-- |§2.3.4
type EncryptedAssertion = EncryptedElement Assertion

-- |§2.4.1
data Subject = Subject
  { subjectIdentifier :: Maybe (PossiblyEncrypted Identifier)
  , subjectConfirmation :: [SubjectConfirmation]
  }

noSubject :: Subject
noSubject = Subject Nothing []

-- |§2.4.1.1
data SubjectConfirmation = SubjectConfirmation
  { subjectConfirmationMethod :: ConfirmationMethod
  , subjectConfirmationIdentifier :: Maybe (PossiblyEncrypted Identifier)
  , subjectConfirmationData :: SubjectConfirmationData
  }

-- |§2.4.1.2
data SubjectConfirmationData = SubjectConfirmationData
  { subjectConfirmationNotBefore
  , subjectConfirmationNotOnOrAfter :: Maybe DateTime
  , subjectConfirmationRecipient :: Maybe AnyURI
  , subjectConfirmationInResponseTo :: Maybe ID
  , subjectConfirmationAddress :: IP
  , subjectConfirmationXML :: Nodes
  }

-- |§2.5.1
data Conditions = Conditions
  { conditionsNotBefore
  , conditionsNotOnOrAfter :: Maybe DateTime
  , conditions :: [ConditionElement]
  , conditionsOneTimeUse :: Bool
  , conditionsProxyRestriction :: Maybe ProxyRestriction
  }
data ConditionElement
  = ConditionAudienceRestriction (List1 Audience) -- ^§2.5.1.4
  | Condition Node -- ^§2.5.1.3

-- |§2.5.1.4
newtype Audience = Audience AnyURI

-- |§2.5.1.6
data ProxyRestriction = ProxyRestriction
  { proxyRestrictionCount :: Maybe Word
  , proxyRestrictionAudience :: [Audience]
  }

-- |§2.6.1
type Advice = [AdviceElement]
data AdviceElement
  = AdviceAssertion AssertionRef
  | Advice Node

-- |§2.7.1
data Statement
  = StatementAuthn AuthnStatement
  | StatementAttributute AttributeStatement
  | StatementAuthzDecision AuthzDecisionStatement
  | Statement Node

-- |§2.7.2
data AuthnStatement = AuthnStatement
  { authnStatementInstant :: DateTime
  , authnStatementSessionIndex :: Maybe XString
  , authnStatementSessionNotOnOrAfter :: Maybe DateTime
  , authnStatementSubjectLocality :: Maybe SubjectLocality
  , authnStatementContext :: AuthnContext
  }

-- |§2.7.2.1
data SubjectLocality = SubjectLocality
  { subjectLocalityAddress :: Maybe IP
  , subjectLocalityDNSName :: Maybe XString
  }

-- |§2.7.2.2
data AuthnContext = AuthnContext
  { authnContextClassRef :: Maybe AnyURI
  , authnContextDecl :: Maybe AuthnContextDecl
  , authnContextAuthenticatingAuthority :: [AnyURI]
  }

data AuthnContextDecl
  = AuthnContextDecl Node
  | AuthnContextDeclRef AnyURI

-- |§2.7.3
newtype AttributeStatement = AttributeStatement (List1 (PossiblyEncrypted Attribute))

-- |§2.7.3.1
data Attribute = Attribute
  { attributeName :: XString
  , attributeNameFormat :: PreidentifiedURI AttributeNameFormat
  , attributeFriendlyName :: Maybe XString
  , attributeXML :: Nodes -- attributes
  , attributeValues :: [AttributeValue]
  }

-- |§2.7.3.1.1
newtype AttributeValue = AttributeValue Nodes

-- |§2.7.3.2
type EncryptedAttribute = EncryptedElement Attribute

-- |§2.7.4
data AuthzDecisionStatement = AuthzDecisionStatement
  { authzDecisionStatementResource :: AnyURI
  , authzDecisionStatementDecision :: DecisionType
  , authzDecisionStatementAction :: List1 Action
  , authzDecisionStatementEvidence :: Maybe Evidence
  }

-- |§2.7.4.1
data DecisionType
  = DecisionTypePermit
  | DecisionTypeDeny
  | DecisionTypeIndeterminate

-- |§2.7.4.2
data Action = Action
  { actionNamespace :: PreidentifiedURI ActionNamespace
  , action :: XString
  }

-- |§2.7.4.3
type Evidence = AssertionRef
