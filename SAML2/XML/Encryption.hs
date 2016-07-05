-- |
-- XML Encryption Syntax and Processing
--
-- <http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/> (selected portions)
module SAML2.XML.Encryption where

import qualified SAML2.XML as XML

data EncryptedElement a = EncryptedElement
  { encryptedData :: XML.Node
  , encryptedKey :: XML.Nodes
  }

data PossiblyEncrypted a
  = NotEncrypted !a
  | SoEncrypted (EncryptedElement a)

