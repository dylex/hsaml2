{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
-- |
-- SAML Assertions
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf saml-core-2.0-os> §2
module SAML2.Core.Assertions where

import qualified Text.XML.HXT.Arrow.Pickle.Schema as XPS

import SAML2.XML
import qualified SAML2.XML.Pickle as XP
import qualified SAML2.XML.Schema as XS
import qualified SAML2.XML.Encryption as XEnc
import qualified SAML2.XML.Signature as DS
import SAML2.Core.Namespaces
import SAML2.Core.Versioning
import SAML2.Core.Identifiers
import SAML2.Profiles.ConfirmationMethod

ns :: Namespace
ns = mkNamespace "saml" $ samlURN SAML20 ["assertion"]

nsName :: XString -> QName
nsName = mkNName ns

xpElem :: String -> XP.PU a -> XP.PU a
xpElem = XP.xpElemQN . nsName

-- |§2.2.1
data BaseID id = BaseID
  { baseNameQualifier :: Maybe XString
  , baseSPNameQualifier :: Maybe XString
  , baseID :: !id
  } deriving (Eq, Show)

xpBaseID :: XP.PU id -> XP.PU (BaseID id)
xpBaseID idp = [XP.biCase|((n, s), i) <-> BaseID n s i|]
  XP.>$<  (XP.xpAttrImplied "NameQualifier"   XS.xpString
    XP.>*< XP.xpAttrImplied "SPNameQualifier" XS.xpString
    XP.>*< idp)

-- |§2.2.3
data NameID = NameID
  { nameBaseID :: BaseID XString
  , nameIDFormat :: PreidentifiedURI NameIDFormat
  , nameSPProvidedID :: Maybe XString
  } deriving (Eq, Show)

instance XP.XmlPickler NameID where
  xpickle = xpElem "NameID" $
    [XP.biCase|((f, p), b) <-> NameID b f p|]
    XP.>$<  (XP.xpDefault (Preidentified NameIDFormatUnspecified) (XP.xpAttr "Format" XP.xpickle)
      XP.>*< XP.xpAttrImplied "SPProvidedID" XS.xpString
      XP.>*< xpBaseID XS.xpString)

type EncryptedNameID = EncryptedElement NameID

instance XP.XmlPickler EncryptedNameID where
  xpickle = xpElem "EncryptedID" xpEncryptedElement

data Identifier
  = IdentifierName NameID
  | IdentifierBase (BaseID Nodes)
  deriving (Eq, Show)

instance XP.XmlPickler Identifier where
  xpickle = [XP.biCase|
      Left n <-> IdentifierName n
      Right b <-> IdentifierBase b |]
    XP.>$< (XP.xpickle XP.>|< xpElem "BaseID" (xpBaseID XP.xpTrees))

-- |§2.2.4
type EncryptedID = EncryptedElement Identifier

instance XP.XmlPickler EncryptedID where
  xpickle = xpElem "EncryptedID" xpEncryptedElement

data EncryptedElement a = EncryptedElement
  { encryptedData :: XEnc.EncryptedData
  , encryptedKey :: [XEnc.EncryptedKey]
  } deriving (Eq, Show)

xpEncryptedElement :: XP.PU (EncryptedElement a)
xpEncryptedElement = [XP.biCase|(d, k) <-> EncryptedElement d k|]
  XP.>$< (XP.xpickle
    XP.>*< XP.xpList XP.xpickle)

data PossiblyEncrypted a
  = NotEncrypted !a
  | SoEncrypted (EncryptedElement a)
  deriving (Eq, Show)

xpPossiblyEncrypted :: (XP.XmlPickler a, XP.XmlPickler (EncryptedElement a)) => XP.PU (PossiblyEncrypted a)
xpPossiblyEncrypted = [XP.biCase|
    Left a <-> NotEncrypted a
    Right a <-> SoEncrypted a |]
  XP.>$< (XP.xpickle XP.>|< XP.xpickle)

data AssertionRef
  = AssertionRefID AssertionIDRef
  | AssertionURIRef AnyURI -- ^§2.3.2
  | AssertionRef (PossiblyEncrypted Assertion)
  deriving (Eq, Show)

instance XP.XmlPickler AssertionRef where
  xpickle = [XP.biCase|
      Left (Left i) <-> AssertionRefID i
      Left (Right u) <-> AssertionURIRef u
      Right a <-> AssertionRef a|]
    XP.>$<  (XP.xpickle
      XP.>|< xpElem "AssertionURIRef" XS.xpAnyURI
      XP.>|< xpPossiblyEncrypted)

-- |§2.2.5
newtype Issuer = Issuer NameID
  deriving (Eq, Show)

instance XP.XmlPickler Issuer where
  xpickle = xpElem "Issuer" $ [XP.biCase|
      n <-> Issuer n|]
    XP.>$< XP.xpickle

-- |§2.3.1
newtype AssertionIDRef = AssertionIDRef ID
  deriving (Eq, Show)

instance XP.XmlPickler AssertionIDRef where
  xpickle = xpElem "AssertionIDRef" $ [XP.biCase|
      i <-> AssertionIDRef i|]
    XP.>$< XS.xpID

-- |§2.3.3
data Assertion = Assertion
  { assertionVersion :: SAMLVersion
  , assertionID :: ID
  , assertionIssueInstant :: DateTime
  , assertionIssuer :: Issuer
  , assertionSignature :: Maybe DS.Signature
  , assertionSubject :: Subject -- ^use 'noSubject' to omit
  , assertionConditions :: Maybe Conditions
  , assertionAdvice :: Maybe Advice
  , assertionStatement :: [AssertionStatement]
  } deriving (Eq, Show)

instance XP.XmlPickler Assertion where
  xpickle = xpElem "Assertion" $
    [XP.biCase|
      ((((((((v, i), t), n), s), Nothing), c), a), l) <-> Assertion v i t n s (Subject Nothing []) c a l
      ((((((((v, i), t), n), s), Just r), c), a), l) <-> Assertion v i t n s r c a l|] 
    XP.>$<  (XP.xpAttr "Version" XP.xpickle
      XP.>*< XP.xpAttr "ID" XS.xpID
      XP.>*< XP.xpAttr "IssueInstant" XS.xpDateTime
      XP.>*< XP.xpickle
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption (xpElem "Advice" $ XP.xpList XP.xpickle)
      XP.>*< XP.xpList XP.xpickle)

data AssertionStatement
  = AssertionStatement Statement
  | AssertionAuthnStatement AuthnStatement
  | AssertionAuthzDecisionStatement AuthzDecisionStatement
  | AssertionAttributeStatement AttributeStatement
  deriving (Eq, Show)

instance XP.XmlPickler AssertionStatement where
  xpickle = [XP.biCase|
      Left (Left (Left s)) <-> AssertionStatement s
      Left (Left (Right s)) <-> AssertionAuthnStatement s
      Left (Right s) <-> AssertionAuthzDecisionStatement s
      Right s <-> AssertionAttributeStatement s|]
    XP.>$<  (XP.xpickle
      XP.>|< XP.xpickle
      XP.>|< XP.xpickle
      XP.>|< XP.xpickle)

-- |§2.3.4
type EncryptedAssertion = EncryptedElement Assertion

instance XP.XmlPickler EncryptedAssertion where
  xpickle = xpElem "EncryptedAssertion" xpEncryptedElement

-- |§2.4.1
data Subject = Subject
  { subjectIdentifier :: Maybe (PossiblyEncrypted Identifier)
  , subjectConfirmation :: [SubjectConfirmation]
  } deriving (Eq, Show)

instance XP.XmlPickler Subject where
  xpickle = xpElem "Subject" $ [XP.biCase|
      (i, c) <-> Subject i c|]
    XP.>$<  (XP.xpOption xpPossiblyEncrypted
      XP.>*< XP.xpList XP.xpickle)

noSubject :: Subject
noSubject = Subject Nothing []

-- |§2.4.1.1
data SubjectConfirmation = SubjectConfirmation
  { subjectConfirmationMethod :: PreidentifiedURI ConfirmationMethod
  , subjectConfirmationIdentifier :: Maybe (PossiblyEncrypted Identifier)
  , subjectConfirmationData :: Maybe SubjectConfirmationData
  } deriving (Eq, Show)

instance XP.XmlPickler SubjectConfirmation where
  xpickle = xpElem "SubjectConfirmation" $ [XP.biCase|
      ((m, i), d) <-> SubjectConfirmation m i d|]
    XP.>$<  (XP.xpAttr "Method" XP.xpickle
      XP.>*< XP.xpOption xpPossiblyEncrypted
      XP.>*< XP.xpOption XP.xpickle)

-- |§2.4.1.2
data SubjectConfirmationData = SubjectConfirmationData
  { subjectConfirmationNotBefore
  , subjectConfirmationNotOnOrAfter :: Maybe DateTime
  , subjectConfirmationRecipient :: Maybe AnyURI
  , subjectConfirmationInResponseTo :: Maybe ID
  , subjectConfirmationAddress :: Maybe IP
  , subjectConfirmationKeyInfo :: [DS.KeyInfo]
  , subjectConfirmationXML :: Nodes
  } deriving (Eq, Show)

instance XP.XmlPickler SubjectConfirmationData where
  xpickle = xpElem "SubjectConfirmationData" $ [XP.biCase|
      ((((((s, e), r), i), a), k), x) <-> SubjectConfirmationData s e r i a k x|]
    XP.>$<  (XP.xpAttrImplied "NotBefore" XS.xpDateTime
      XP.>*< XP.xpAttrImplied "NotOnOrAfter" XS.xpDateTime
      XP.>*< XP.xpAttrImplied "Recipient" XS.xpAnyURI
      XP.>*< XP.xpAttrImplied "InResponseTo" XS.xpNCName
      XP.>*< XP.xpAttrImplied "Address" xpIP
      XP.>*< XP.xpList XP.xpickle
      XP.>*< XP.xpTrees)

-- |§2.5.1
data Conditions = Conditions
  { conditionsNotBefore
  , conditionsNotOnOrAfter :: Maybe DateTime
  , conditions :: [Condition]
  } deriving (Eq, Show)

instance XP.XmlPickler Conditions where
  xpickle = xpElem "Conditions" $ [XP.biCase|
      ((s, e), c) <-> Conditions s e c|]
    XP.>$<  (XP.xpAttrImplied "NotBefore" XS.xpDateTime
      XP.>*< XP.xpAttrImplied "NotOnOrAfter" XS.xpDateTime
      XP.>*< XP.xpList XP.xpickle)

data Condition
  = Condition Node -- ^§2.5.1.3
  | AudienceRestriction (List1 Audience) -- ^§2.5.1.4
  | OneTimeUse -- ^§2.5.1.5
  | ProxyRestriction
    { proxyRestrictionCount :: Maybe XS.NonNegativeInteger
    , proxyRestrictionAudience :: [Audience]
    } -- ^§2.5.1.6
  deriving (Eq, Show)

instance XP.XmlPickler Condition where
  xpickle = [XP.biCase|
      Left (Left (Left a)) <-> AudienceRestriction a
      Left (Left (Right ())) <-> OneTimeUse
      Left (Right (c, a)) <-> ProxyRestriction c a
      Right x <-> Condition x|]
    XP.>$<  (xpElem "AudienceRestriction" (xpList1 XP.xpickle)
      XP.>|< xpElem "OneTimeUse" XP.xpUnit
      XP.>|< xpElem "ProxyRestriction"
              (XP.xpAttrImplied "Count" XS.xpNonNegativeInteger
        XP.>*< XP.xpList XP.xpickle)
      XP.>|< XP.xpTree)

-- |§2.5.1.4
newtype Audience = Audience AnyURI
  deriving (Eq, Show)

instance XP.XmlPickler Audience where
  xpickle = xpElem "Audience" $ [XP.biCase|
      u <-> Audience u|]
    XP.>$< XS.xpAnyURI

-- |§2.6.1
type Advice = [AdviceElement]
data AdviceElement
  = AdviceAssertion AssertionRef
  | Advice Node
  deriving (Eq, Show)

instance XP.XmlPickler AdviceElement where
  xpickle = [XP.biCase|
      Left a <-> AdviceAssertion a
      Right x <-> Advice x|]
    XP.>$<  (XP.xpickle
      XP.>|< XP.xpTree)

-- |§2.7.1
data Statement
  = StatementAuthn AuthnStatement
  | StatementAttribute AttributeStatement
  | StatementAuthzDecision AuthzDecisionStatement
  | Statement Node
  deriving (Eq, Show)

instance XP.XmlPickler Statement where
  xpickle = [XP.biCase|
      Left (Left (Left s)) <-> StatementAuthn s
      Left (Left (Right s)) <-> StatementAttribute s
      Left (Right s) <-> StatementAuthzDecision s
      Right x <-> Statement x|]
    XP.>$<  (XP.xpickle
      XP.>|< XP.xpickle
      XP.>|< XP.xpickle
      XP.>|< XP.xpTree)

-- |§2.7.2
data AuthnStatement = AuthnStatement
  { authnStatementInstant :: DateTime
  , authnStatementSessionIndex :: Maybe XString
  , authnStatementSessionNotOnOrAfter :: Maybe DateTime
  , authnStatementSubjectLocality :: Maybe SubjectLocality
  , authnStatementContext :: AuthnContext
  } deriving (Eq, Show)

instance XP.XmlPickler AuthnStatement where
  xpickle = xpElem "AuthnStatement" $ [XP.biCase|
      ((((t, i), e), l), c) <-> AuthnStatement t i e l c|]
    XP.>$<  (XP.xpAttr "AuthnInstant" XS.xpDateTime
      XP.>*< XP.xpAttrImplied "SessionIndex" XS.xpString
      XP.>*< XP.xpAttrImplied "SessionNotOnOrAfter" XS.xpDateTime
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpickle)

-- |§2.7.2.1
data SubjectLocality = SubjectLocality
  { subjectLocalityAddress :: Maybe IP
  , subjectLocalityDNSName :: Maybe XString
  } deriving (Eq, Show)

instance XP.XmlPickler SubjectLocality where
  xpickle = xpElem "SubjectLocality" $ [XP.biCase|
      (a, d) <-> SubjectLocality a d|]
    XP.>$<  (XP.xpAttrImplied "Address" xpIP
      XP.>*< XP.xpAttrImplied "DNSName" XS.xpString)

-- |§2.7.2.2
data AuthnContext = AuthnContext
  { authnContextClassRef :: Maybe AnyURI
  , authnContextDecl :: Maybe AuthnContextDecl
  , authnContextAuthenticatingAuthority :: [AnyURI]
  } deriving (Eq, Show)

instance XP.XmlPickler AuthnContext where
  xpickle = xpElem "AuthnContext" $ [XP.biCase|
      ((c, d), a) <-> AuthnContext c d a|]
    XP.>$<  (XP.xpOption (xpElem "AuthnContextClassRef" XS.xpAnyURI)
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpList (xpElem "AuthenticatingAuthority" XS.xpAnyURI))

data AuthnContextDecl
  = AuthnContextDecl Node
  | AuthnContextDeclRef AnyURI
  deriving (Eq, Show)

instance XP.XmlPickler AuthnContextDecl where
  xpickle = [XP.biCase|
      Left d <-> AuthnContextDecl d
      Right r <-> AuthnContextDeclRef r|]
    XP.>$<  (xpElem "AuthnContextDecl" XP.xpTree
      XP.>|< xpElem "AuthnContextDeclRef" XS.xpAnyURI)

-- |§2.7.3
newtype AttributeStatement = AttributeStatement (List1 (PossiblyEncrypted Attribute))
  deriving (Eq, Show)

instance XP.XmlPickler AttributeStatement where
  xpickle = xpElem "AttributeStatement" $ [XP.biCase|
      l <-> AttributeStatement l|]
    XP.>$< xpList1 xpPossiblyEncrypted

-- |§2.7.3.1
data Attribute = Attribute
  { attributeName :: XString
  , attributeNameFormat :: PreidentifiedURI AttributeNameFormat
  , attributeFriendlyName :: Maybe XString
  , attributeXML :: Nodes -- attributes
  , attributeValues :: [Nodes] -- ^§2.7.3.1.1
  } deriving (Eq, Show)

instance XP.XmlPickler Attribute where
  xpickle = xpElem "Attribute" $ [XP.biCase|
      ((((n, f), u), v), x) <-> Attribute n f u x v|]
    XP.>$<  (XP.xpAttr "Name" XS.xpString
      XP.>*< XP.xpDefault (Preidentified AttributeNameFormatUnspecified) (XP.xpAttr "NameFormat" XP.xpickle)
      XP.>*< XP.xpAttrImplied "FriedlyName" XS.xpString
      XP.>*< XP.xpCheckEmptyContents (XP.xpList (xpElem "AttributeValue" XP.xpTrees))
      XP.>*< XP.xpTrees)

-- |§2.7.3.2
type EncryptedAttribute = EncryptedElement Attribute

instance XP.XmlPickler EncryptedAttribute where
  xpickle = xpElem "EncryptedAttribute" xpEncryptedElement

-- |§2.7.4
data AuthzDecisionStatement = AuthzDecisionStatement
  { authzDecisionStatementResource :: AnyURI
  , authzDecisionStatementDecision :: DecisionType
  , authzDecisionStatementAction :: List1 Action
  , authzDecisionStatementEvidence :: Evidence
  } deriving (Eq, Show)

instance XP.XmlPickler AuthzDecisionStatement where
  xpickle = xpElem "AuthzDecisionStatement" $ [XP.biCase|
      (((r, d), a), e) <-> AuthzDecisionStatement r d a e|]
    XP.>$<  (XP.xpAttr "Resource" XS.xpAnyURI
      XP.>*< XP.xpAttr "Decision" XP.xpickle
      XP.>*< xpList1 XP.xpickle
      XP.>*< XP.xpickle)

-- |§2.7.4.1
data DecisionType
  = DecisionTypePermit
  | DecisionTypeDeny
  | DecisionTypeIndeterminate
  deriving (Eq, Enum, Bounded, Show)

instance XP.XmlPickler DecisionType where
  xpickle = xpEnum (XP.xpTextDT (XPS.scDT (namespaceURI ns) "DecisionType" [])) "DecisionType" g where
    g DecisionTypePermit = "Permit"
    g DecisionTypeDeny = "Deny"
    g DecisionTypeIndeterminate = "Indeterminate"

-- |§2.7.4.2
data Action = Action
  { actionNamespace :: PreidentifiedURI ActionNamespace
  , action :: XString
  } deriving (Eq, Show)

instance XP.XmlPickler Action where
  xpickle = xpElem "Action" $ [XP.biCase|
      (n, a) <-> Action n a|]
    XP.>$<  (XP.xpDefault (Preidentified ActionNamespaceRWEDCNegation) (XP.xpAttr "Namespace" XP.xpickle)
      XP.>*< XP.xpText0)

-- |§2.7.4.3
newtype Evidence = Evidence [AssertionRef]
  deriving (Eq, Show)

instance XP.XmlPickler Evidence where
  xpickle = [XP.biCase|
      Nothing <-> Evidence []
      Just l <-> Evidence l|]
    XP.>$< XP.xpOption (xpElem "Evidence" $ XP.xpList1 XP.xpickle)
