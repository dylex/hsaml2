{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
-- |
-- XML Encryption Syntax and Processing
--
-- <http://www.w3.org/TR/xmlenc-core1/> (selected portions)
module SAML2.XML.Encryption where

import SAML2.XML
import qualified Text.XML.HXT.Arrow.Pickle.Xml.Invertible as XP
import qualified SAML2.XML.Schema as XS
import qualified SAML2.XML.Signature.Types as DS

nsFrag :: String -> URI
nsFrag = httpURI "www.w3.org" "/2001/04/xmlenc" "" . ('#':)

ns :: Namespace 
ns = mkNamespace "xenc" $ nsFrag ""

xpElem :: String -> XP.PU a -> XP.PU a
xpElem = xpTrimElemNS ns

-- |§3.1
data EncryptedType = EncryptedType
  { encryptedID :: Maybe ID
  , encryptedType :: Maybe AnyURI
  , encryptedMimeType :: Maybe XString
  , encryptedEncoding :: Maybe (IdentifiedURI DS.EncodingAlgorithm)
  , encryptedEncryptionMethod :: Maybe EncryptionMethod
  , encryptedKeyInfo :: Maybe DS.KeyInfo
  , encryptedCipherData :: CipherData
  , encryptedEncryptionProperties :: Maybe EncryptionProperties
  } deriving (Eq, Show)

instance XP.XmlPickler EncryptedType where
  xpickle = [XP.biCase|(((((((i, t), m), e), c), k), d), p) <-> EncryptedType i t m e c k d p|]
    XP.>$<  (XP.xpAttrImplied "Id" XS.xpID
      XP.>*< XP.xpAttrImplied "Type" XS.xpAnyURI
      XP.>*< XP.xpAttrImplied "MimeType" XS.xpString
      XP.>*< XP.xpAttrImplied "Encoding" XP.xpickle
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpickle
      XP.>*< XP.xpOption XP.xpickle)

-- |§3.2
data EncryptionMethod = EncryptionMethod
  { encryptionAlgorithm :: IdentifiedURI EncryptionAlgorithm
  , encryptionKeySize :: Maybe Int
  , encryptionOAEPparams :: Maybe XS.Base64Binary
  , encryptionDigestMethod :: Maybe DS.DigestMethod
  , encryption :: Nodes
  } deriving (Eq, Show)

xpEncryptionMethodType :: XP.PU EncryptionMethod
xpEncryptionMethodType =
  [XP.biCase|((((a, s), p), d), x) <-> EncryptionMethod a s p d x|] 
  XP.>$< (XP.xpAttr "Algorithm" XP.xpickle
    XP.>*< XP.xpOption (xpElem "KeySize" XP.xpickle)
    XP.>*< XP.xpOption (xpElem "OAEPparams" XS.xpBase64Binary)
    XP.>*< XP.xpOption XP.xpickle
    XP.>*< XP.xpAnyCont)

instance XP.XmlPickler EncryptionMethod where
  xpickle = xpElem "EncryptionMethod" xpEncryptionMethodType

-- |§3.3
data CipherData
  = CipherValue XS.Base64Binary
  | CipherReference
    { cipherURI :: AnyURI
    , cipherTransforms :: List1 DS.Transform
    }
  deriving (Eq, Show)

instance XP.XmlPickler CipherData where
  xpickle = xpElem "CipherData" $
    [XP.biCase|
      Left b <-> CipherValue b
      Right (u, t) <-> CipherReference u t |]
    XP.>$<  (xpElem "CipherValue" XS.xpBase64Binary
      XP.>|< xpElem "CipherReference"
              (XP.xpAttr "URI" XS.xpAnyURI
        XP.>*< xpElem "Transforms" (xpList1 XP.xpickle)))

-- |§3.4
newtype EncryptedData = EncryptedData{ encryptedData :: EncryptedType }
  deriving (Eq, Show)

instance XP.XmlPickler EncryptedData where
  xpickle = xpElem "EncryptedData" $
    [XP.biCase|e <-> EncryptedData e|] 
    XP.>$< XP.xpickle

-- |§3.5.1
data EncryptedKey = EncryptedKey
  { encryptedKey :: !EncryptedType
  , encryptedKeyRecipient :: Maybe XString
  , encryptedKeyReferenceList :: [Reference] -- ^empty for missing
  , encryptedKeyCarriedKeyName :: Maybe XString
  } deriving (Eq, Show)

instance XP.XmlPickler EncryptedKey where
  xpickle = xpElem "EncryptedKey" $
    [XP.biCase|
      (e, ((r, Nothing), n)) <-> EncryptedKey e r [] n
      (e, ((r, Just l), n)) <-> EncryptedKey e r l n
    |] 
    XP.>$< (XP.xpickle
      XP.>*<  (XP.xpAttrImplied "Recipient" XS.xpString
        XP.>*< XP.xpOption (xpElem "ReferenceList" $ XP.xpList1 XP.xpickle)
        XP.>*< XP.xpOption (xpElem "CarriedKeyName" XS.xpString)))

-- |§3.6
data Reference
  = DataReference
    { referenceURI :: URI
    , reference :: Nodes
    }
  | KeyReference
    { referenceURI :: URI
    , reference :: Nodes
    }
  deriving (Eq, Show)

instance XP.XmlPickler Reference where
  xpickle = [XP.biCase|
      Left (u, r) <-> DataReference u r
      Right (u, r) <-> KeyReference u r |]
    XP.>$< (refs "DataReference" XP.>|< refs "KeyReference")
    where
    refs n = xpElem n
      $ XP.xpAttr "URI" XS.xpAnyURI
      XP.>*< XP.xpList xpTrimAnyElem

-- |§3.7
data EncryptionProperties = EncryptionProperties
  { encryptionPropertiesId :: Maybe ID
  , encryptionProperties :: List1 EncryptionProperty
  } deriving (Eq, Show)

instance XP.XmlPickler EncryptionProperties where
  xpickle = xpElem "EncryptionProperties" $
    [XP.biCase|(i, l) <-> EncryptionProperties i l|] 
    XP.>$<  (XP.xpAttrImplied "Id" XS.xpID
      XP.>*< xpList1 XP.xpickle)

data EncryptionProperty = EncryptionProperty
  { encryptionPropertyId :: Maybe ID
  , encryptionPropertyTarget :: Maybe AnyURI
  , encryptionProperty :: Nodes
  } deriving (Eq, Show)

instance XP.XmlPickler EncryptionProperty where
  xpickle = xpElem "EncryptionProperty" $
    [XP.biCase|((i, t), x) <-> EncryptionProperty i t x|] 
    XP.>$<  (XP.xpAttrImplied "Id" XS.xpID
      XP.>*< XP.xpAttrImplied "Target" XS.xpAnyURI
      XP.>*< XP.xpAny)

-- |§5.1
data EncryptionAlgorithm
  = BlockEncryptionTripleDES -- ^§5.2.2
  | BlockEncryptionAES128 -- ^§5.2.3
  | BlockEncryptionAES192 -- ^§5.2.3
  | BlockEncryptionAES256 -- ^§5.2.3
  | BlockEncryptionAES128GCM -- ^§5.2.4
  | BlockEncryptionAES192GCM -- ^§5.2.4
  | BlockEncryptionAES256GCM -- ^§5.2.4
  | KeyTransportRSA1_5 -- ^§5.5.1
  | KeyTransportRSAOAEPMGF1P -- ^§5.5.2
  | KeyTransportRSAOAEP -- ^§5.5.2
  deriving (Eq, Bounded, Enum, Show)

instance Identifiable URI EncryptionAlgorithm where
  identifier BlockEncryptionTripleDES = nsFrag "tripledes-cbc"
  identifier BlockEncryptionAES128 = nsFrag "aes128-cbc"
  identifier BlockEncryptionAES256 = nsFrag "aes256-cbc"
  identifier BlockEncryptionAES192 = nsFrag "aes192-cbc"
  identifier BlockEncryptionAES128GCM = httpURI "www.w3.org" "/2009/xmlenc11" "" "#aes128-gcm"
  identifier BlockEncryptionAES192GCM = httpURI "www.w3.org" "/2009/xmlenc11" "" "#aes192-gcm"
  identifier BlockEncryptionAES256GCM = httpURI "www.w3.org" "/2009/xmlenc11" "" "#aes256-gcm"
  identifier KeyTransportRSA1_5 = nsFrag "rsa-1_5"
  identifier KeyTransportRSAOAEPMGF1P = nsFrag "rsa-oaep-mgf1p"
  identifier KeyTransportRSAOAEP = httpURI "www.w3.org" "/2009/xmlenc11" "" "#rsa-oaep"

-- |§5.5
data AgreementMethod = AgreementMethod
  { agreementMethodAlgorithm :: IdentifiedURI EncryptionAlgorithm
  , agreementMethodKA_Nonce :: Maybe XS.Base64Binary
  , agreementMethodDigestMethod :: Maybe DS.DigestMethod
  -- Nodes...
  , agreementMethodOriginatorKeyInfo :: Maybe DS.KeyInfo
  , agreementMethodRecipientKeyInfo :: Maybe DS.KeyInfo
  }

instance XP.XmlPickler AgreementMethod where
  xpickle = xpElem "AgreementMethod" $
    [XP.biCase|((((a, n), d), o), r) <-> AgreementMethod a n d o r|]
    XP.>$< (XP.xpAttr "Algorithm" XP.xpickle
      XP.>*< XP.xpOption (xpElem "KA-Nonce" XS.xpBase64Binary)
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption (xpElem "OriginatorKeyInfo" DS.xpKeyInfoType)
      XP.>*< XP.xpOption (xpElem "RecipientKeyInfo" DS.xpKeyInfoType))
