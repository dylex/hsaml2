{-# LANGUAGE OverloadedStrings #-}
module XML.Encryption (tests) where

import Data.List.NonEmpty (NonEmpty(..))
import qualified Test.HUnit as U
import qualified Text.XML.HXT.Arrow.Pickle.Xml as XP
import qualified Text.XML.HXT.DOM.QualifiedName as HXT
import qualified Text.XML.HXT.DOM.XmlNode as HXT

import SAML2.XML
import SAML2.XML.Signature
import SAML2.XML.Encryption

import XML

tests :: U.Test
tests = U.test
  [ testXML "test/XML/encryption-example.xml" $
    EncryptedData $ EncryptedType (Just "eg1")
      Nothing
      Nothing
      Nothing
      (Just $ EncryptionMethod
        (Preidentified KeyTransportRSAOAEP)
        (Just 256)
        (Just "\246U\174\221")
        (Just $ DigestMethod
          (Preidentified DigestSHA1)
          [])
        [])
      (Just $ KeyInfo Nothing
        (KeyInfoKeyName "Joseph"
        :| KeyInfoRetrievalMethod
          (readURI "http://exmample.org/Reagle/PublicKey")
          (Just $ readURI "http://www.w3.org/2001/04/xmlenc#EncryptedKey")
          Nothing
        : KeyInfoElement (pickleElem XP.xpickle $ EncryptedKey
          (EncryptedType Nothing
            Nothing
            Nothing
            Nothing
            (Just $ EncryptionMethod
              (Preidentified BlockEncryptionTripleDES)
              Nothing
              Nothing
              Nothing
              [])
            Nothing
            (CipherValue "\169\153>6G\ACK\129j\186>%qxP\194l\156\208\216\157")
            Nothing)
          Nothing
          [ KeyReference
            (readURI "http://exmample.org/foo2")
            []
          , DataReference
            (readURI "http://exmample.org/foo1")
            []
          ]
          Nothing)
        : KeyInfoElement (pickleElem XP.xpickle $ AgreementMethod
          (Unidentified (readURI "example:Agreement/Algorithm"))
          (Just "foo")
          (Just $ DigestMethod
            (Preidentified DigestSHA1)
            [])
          (Just $ KeyInfo Nothing $
            KeyInfoKeyValue (RSAKeyValue
              124965805205214
              124965805205214)
            :| [])
          (Just $ KeyInfo Nothing $
            KeyInfoKeyValue (RSAKeyValue
              124965805205214
              124965805205214)
            :| []))
        : []))
      (CipherReference
        (readURI "http://example.org/pgpkeys/reagle.b64")
        (Transform
          (Preidentified TransformBase64)
          []
        :| []))
      (Just $ EncryptionProperties Nothing $
        EncryptionProperty (Just "ep2")
          (Just $ readURI "#eg1")
          [HXT.mkElement (HXT.mkNsName "p" "http://www.w3.org/1999/xhtml")
            []
            [HXT.mkText "This XML document tests the schema for ambigous content."]]
        :| [])

  ]
