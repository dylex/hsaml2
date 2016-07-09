{-# LANGUAGE FlexibleContexts, TypeSynonymInstances, FlexibleInstances, QuasiQuotes #-}
-- |
-- XML Encryption Syntax and Processing
--
-- <http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/> (selected portions)
module SAML2.XML.Encryption where

import SAML2.XML
import qualified SAML2.XML.Pickle as XP
import qualified SAML2.XML.Schema as XS
import qualified SAML2.XML.Signature as DS

nsFrag :: String -> URI
nsFrag = httpURI "www.w3.org" "/2001/04/xmlenc" "" . ('#':)

ns :: Namespace 
ns = mkNamespace "xenc" $ nsFrag ""

nsName :: XString -> QName
nsName = mkNName ns

-- |§3.1
data EncryptedType = EncryptedType
  { encryptedID :: Maybe ID
  , encryptedType :: Maybe AnyURI
  , encryptedMimeType :: Maybe XString
  , encryptedEncoding :: Maybe (PreidentifiedURI DS.EncodingAlgorithm)
  , encryptedEncryptionMethod :: Maybe EncryptionMethod
  , encryptedKeyInfo :: Maybe DS.KeyInfo
  , encryptedCipherData :: CipherData
  , encryptedEncryptionProperties :: Maybe EncryptionProperties
  } deriving (Eq, Show)

instance XP.XmlPickler EncryptedType where
  xpickle = [XP.biCase|(((((((i, t), m), e), c), k), d), p) <-> EncryptedType i t m e c k d p|]
    XP.>$<  (XP.xpOption (XP.xpAttr "Id" XS.xpID)
      XP.>*< XP.xpOption (XP.xpAttr "Type" XP.xpickle)
      XP.>*< XP.xpOption (XP.xpAttr "MimeType" XS.xpString)
      XP.>*< XP.xpOption (XP.xpAttr "Encoding" XP.xpickle)
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpickle
      XP.>*< XP.xpOption XP.xpickle)

-- |§3.2
data EncryptionMethod = EncryptionMethod
  { encryptionAlgorithm :: PreidentifiedURI EncryptionAlgorithm
  , encryptionKeySize :: Maybe Int
  , encryptionOAEPparams :: Maybe XS.Base64Binary
  , encryptionDigestMethod :: Maybe DS.DigestMethod
  , encryption :: Nodes
  } deriving (Eq, Show)

instance XP.XmlPickler EncryptionMethod where
  xpickle = XP.xpElemQN (nsName "EncryptionMethod") $
    [XP.biCase|((((a, s), p), d), x) <-> EncryptionMethod a s p d x|] 
    XP.>$< (XP.xpCheckEmptyAttributes (XP.xpAttr "Algorithm" XP.xpickle)
      XP.>*< XP.xpOption (XP.xpElemQN (nsName "KeySize") XP.xpickle)
      XP.>*< XP.xpOption (XP.xpElemQN (nsName "OAEPparams") XS.xpBase64Binary)
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpTrees)

-- |§3.3
data CipherData
  = CipherValue XS.Base64Binary
  | CipherReference
    { cipherURI :: AnyURI
    , cipherTransforms :: List1 DS.Transform
    }
  deriving (Eq, Show)

instance XP.XmlPickler CipherData where
  xpickle = XP.xpElemQN (nsName "CipherData") $
    [XP.biCase|
      Left b <-> CipherValue b
      Right (u, t) <-> CipherReference u t |]
    XP.>$<  (XP.xpElemQN (nsName "CipherValue") XS.xpBase64Binary
      XP.>|< XP.xpElemQN (nsName "CipherReference")
              (XP.xpAttr "URI" XP.xpickle
        XP.>*< XP.xpElemQN (nsName "Transforms") (xpList1 XP.xpickle)))

-- |§3.4
newtype EncryptedData = EncryptedData{ encryptedData :: EncryptedType }
  deriving (Eq, Show)

instance XP.XmlPickler EncryptedData where
  xpickle = XP.xpElemQN (nsName "EncryptedData") $
    [XP.biCase|e <-> EncryptedData e|] 
    XP.>$< XP.xpickle

-- |§3.5.1
data EncryptedKey = EncryptedKey
  { encryptedKey :: EncryptedType
  , encryptedKeyRecipient :: Maybe XString
  , encryptedKeyReferenceList :: [Reference] -- ^empty for missing
  , encryptedKeyCarriedKeyName :: Maybe XString
  } deriving (Eq, Show)

instance XP.XmlPickler EncryptedKey where
  xpickle = XP.xpElemQN (nsName "EncryptedKey") $
    [XP.biCase|
      (e, ((r, Nothing), n)) <-> EncryptedKey e r [] n
      (e, ((r, Just l), n)) <-> EncryptedKey e r l n
    |] 
    XP.>$< (XP.xpickle
      XP.>*<  (XP.xpOption (XP.xpAttr "Recipient" XS.xpString)
        XP.>*< XP.xpOption (XP.xpElemQN (nsName "ReferenceList") $ XP.xpList1 XP.xpickle)
        XP.>*< XP.xpOption (XP.xpElemQN (nsName "CarriedKeyName") XS.xpString)))

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
    refs n = XP.xpElemQN (nsName n)
      $ XP.xpCheckEmptyAttributes (XP.xpAttr "URI" XP.xpickle)
      XP.>*< XP.xpTrees

-- |§3.7
data EncryptionProperties = EncryptionProperties
  { encryptionPropertiesId :: Maybe ID
  , encryptionProperties :: List1 EncryptionProperty
  } deriving (Eq, Show)

instance XP.XmlPickler EncryptionProperties where
  xpickle = XP.xpElemQN (nsName "EncryptionProperties") $
    [XP.biCase|(i, l) <-> EncryptionProperties i l|] 
    XP.>$<  (XP.xpOption (XP.xpAttr "Id" XS.xpID)
      XP.>*< xpList1 XP.xpickle)

data EncryptionProperty = EncryptionProperty
  { encryptionPropertyId :: Maybe ID
  , encryptionPropertyTarget :: Maybe AnyURI
  , encryptionProperty :: Nodes
  } deriving (Eq, Show)

instance XP.XmlPickler EncryptionProperty where
  xpickle = XP.xpElemQN (nsName "EncryptionProperty") $
    [XP.biCase|((i, t), x) <-> EncryptionProperty i t x|] 
    XP.>$<  (XP.xpOption (XP.xpAttr "Id" XS.xpID)
      XP.>*< XP.xpOption (XP.xpAttr "Target" XP.xpickle)
      XP.>*< XP.xpTrees) -- really only should allow xml: attributes

-- |§5.1
data EncryptionAlgorithm
  = BlockEncryptionTripleDES -- ^§5.2.1
  | BlockEncryptionAES128 -- ^§5.2.2
  | BlockEncryptionAES256 -- ^§5.2.2
  | BlockEncryptionAES192 -- ^§5.2.2
  | KeyTransportRSA1_5 -- ^§5.4.1
  | KeyTransportRSAOAEP -- ^§5.4.2
  deriving (Eq, Bounded, Enum, Show)

instance XP.XmlPickler (PreidentifiedURI EncryptionAlgorithm) where
  xpickle = xpPreidentifiedURI f where
    f BlockEncryptionTripleDES = nsFrag "tripledes-cbc"
    f BlockEncryptionAES128 = nsFrag "aes128-cbc"
    f BlockEncryptionAES256 = nsFrag "aes256-cbc"
    f BlockEncryptionAES192 = nsFrag "aes192-cbc"
    f KeyTransportRSA1_5 = nsFrag "rsa-1_5"
    f KeyTransportRSAOAEP = nsFrag "rsa-oaep-mgf1p"

-- |§5.5
data AgreementMethod = AgreementMethod
  { agreementMethodAlgorithm :: PreidentifiedURI EncryptionAlgorithm
  , agreementMethodKA_Nonce :: Maybe XS.Base64Binary
  , agreementMethodDigestMethod :: Maybe DS.DigestMethod
  -- Nodes...
  , agreementMethodOriginatorKeyInfo :: Maybe DS.KeyInfo
  , agreementMethodRecipientKeyInfo :: Maybe DS.KeyInfo
  }

instance XP.XmlPickler AgreementMethod where
  xpickle = XP.xpElemQN (nsName "AgreementMethod") $
    [XP.biCase|((((a, n), d), o), r) <-> AgreementMethod a n d o r|]
    XP.>$< (XP.xpAttr "Algorithm" XP.xpickle
      XP.>*< XP.xpOption (XP.xpElemQN (nsName "KA-Nonce") XS.xpBase64Binary)
      XP.>*< XP.xpOption XP.xpickle
      XP.>*< XP.xpOption (XP.xpElemQN (nsName "OriginatorKeyInfo") DS.xpKeyInfoType)
      XP.>*< XP.xpOption (XP.xpElemQN (nsName "RecipientKeyInfo") DS.xpKeyInfoType))
