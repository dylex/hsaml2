{-# LANGUAGE FlexibleContexts, QuasiQuotes #-}
-- |
-- XML Encryption Syntax and Processing
--
-- <http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/> (selected portions)
module SAML2.XML.Encryption where

import SAML2.XML
import qualified SAML2.XML.Schema as XS
import qualified SAML2.XML.Signature as DS
import qualified SAML2.XML.Pickle as XP

ns :: Namespace 
ns = Namespace "xenc" "http://www.w3.org/2001/04/xmlenc#"

nsName :: XString -> QName
nsName = mkNName ns

-- |§3.1
data EncryptedType = EncryptedType
  { encryptedID :: Maybe ID
  , encryptedType :: Maybe AnyURI
  , encryptedMimeType :: Maybe XString
  , encryptedEncoding :: Maybe AnyURI
  , encryptedEncryptionMethod :: Maybe EncryptionMethod
  , encryptedKeyInfo :: Maybe DS.KeyInfo
  , encryptedCipherData :: CipherData
  , encryptedEncryptionProperties :: Maybe EncryptionProperties
  }

-- |§3.2
data EncryptionMethod = EncryptionMethod
  { encryptionAlgorithm :: AnyURI -- PreidentifiedURI Algorithm
  , encryptionKeySize :: Maybe Int
  , encryptionOAEPparams :: Maybe XS.Base64Binary
  , encryption :: Nodes
  }

instance XP.XmlPickler EncryptionMethod where
  xpickle = XP.xpElemQN (nsName "EncryptionMethod") $
    [XP.biCase|(((a, s), p), x) <-> EncryptionMethod a s p x|] 
    XP.>$< (XP.xpCheckEmptyAttributes (XP.xpAttrQN (nsName "Algorithm") XP.xpickle)
      XP.>*< XP.xpOption (XP.xpElemQN (nsName "KeySize") XP.xpickle)
      XP.>*< XP.xpOption (XP.xpElemQN (nsName "OAEPparams") XS.xpBase64Binary)
      XP.>*< XP.xpTrees)

-- |§3.3
data CipherData
  = CipherValue XS.Base64Binary
  | CipherReference
    { cipherURI :: AnyURI
    , cipherTransforms :: DS.Transforms
    }

instance XP.XmlPickler CipherData where
  xpickle = XP.xpElemQN (nsName "CipherData") $
    [XP.biCase|
      Left b <-> CipherValue b
      Right (u, t) <-> CipherReference u t |]
    XP.>$< (XP.xpElemQN (nsName "CipherValue") XS.xpBase64Binary
      XP.>|< XP.xpAttrQN (nsName "URI") XP.xpickle
        XP.>*< XP.xpickle)

-- |§3.4
newtype EncryptedData = EncryptedData{ encryptedData :: EncryptedType }

-- |§3.5.1
data EncryptedKey = EncryptedKey
  { encryptedKeyRecipient :: Maybe XString
  , encryptedKeyReferenceList :: [Reference] -- ^empty for missing
  , encryptedKeyCarriedKeyName :: Maybe XString
  , encryptedKey :: EncryptedType
  }

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

instance XP.XmlPickler Reference where
  xpickle = [XP.biCase|
      Left (u, r) <-> DataReference u r
      Right (u, r) <-> KeyReference u r |]
    XP.>$< (refs "DataReference" XP.>|< refs "KeyReference")
    where
    refs n = XP.xpElemQN (nsName n)
      $ XP.xpCheckEmptyAttributes (XP.xpAttrQN (nsName "URI") XP.xpickle)
      XP.>*< XP.xpTrees

-- |§3.7
data EncryptionProperties = EncryptionProperties
  { encryptionPropertiesId :: Maybe ID
  , encryptionProperties :: List1 EncryptionProperty
  } deriving (Eq, Show)

instance XP.XmlPickler EncryptionProperties where
  xpickle = XP.xpElemQN (nsName "EncryptionProperties") $
    [XP.biCase|(i, l) <-> EncryptionProperties i l|] 
    XP.>$<  (XP.xpOption (XP.xpAttrQN (nsName "Id") XS.xpID)
      XP.>*< xpList1 XP.xpickle)

data EncryptionProperty = EncryptionProperty
  { encryptionPropertyId :: Maybe ID
  , encryptionPropertyTarget :: Maybe AnyURI
  , encryptionProperty :: Nodes
  } deriving (Eq, Show)

instance XP.XmlPickler EncryptionProperty where
  xpickle = XP.xpElemQN (nsName "EncryptionProperty") $
    [XP.biCase|((i, t), x) <-> EncryptionProperty i t x|] 
    XP.>$<  (XP.xpOption (XP.xpAttrQN (nsName "Id") XS.xpID)
      XP.>*< XP.xpOption (XP.xpAttrQN (nsName "Target") XP.xpickle)
      XP.>*< XP.xpTrees) -- really only should allow xml: attributes
