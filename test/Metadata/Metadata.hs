{-# LANGUAGE OverloadedStrings #-}
module Metadata.Metadata (tests) where

import Data.List.NonEmpty (NonEmpty(..))
import qualified Test.HUnit as U
import qualified Text.XML.HXT.Arrow.Pickle.Xml as XP
import qualified Text.XML.HXT.DOM.QualifiedName as HXT
import qualified Text.XML.HXT.DOM.XmlNode as HXT

import SAML2.XML
import qualified SAML2.XML.Signature as DS
import qualified SAML2.XML.Encryption as XEnc
import SAML2.Core.Identifiers
import qualified SAML2.Core.Assertions as SAML
import qualified SAML2.Core.Protocols as SAMLP
import SAML2.Bindings.Identifiers
import SAML2.Metadata.Metadata

import XML

tests :: U.Test
tests = U.test
  [ testXML "test/Metadata/metadata-idp.xml" $
    EntityDescriptor
      (uri "https://IdentityProvider.com/SAML")
      Nothing
      Nothing
      (Just 31729999.8)
      []
      Nothing
      (Extensions [])
      (Descriptors $
        IDPSSODescriptor
          (RoleDescriptor
            Nothing Nothing Nothing
            [uri $ namespaceURI SAMLP.ns]
            Nothing [] Nothing
            (Extensions [])
            [KeyDescriptor
              KeyTypeSigning
              (DS.KeyInfo
                Nothing
                (DS.KeyName "IdentityProvider.com SSO Key"
                :| []))
              []]
            Nothing
            [])
          (SSODescriptor
            [IndexedEndpoint
              (Endpoint
                (Identified BindingSOAP)
                (uri "https://IdentityProvider.com/SAML/Artifact")
                Nothing [] [])
              0
              True]
            [Endpoint
              (Identified BindingSOAP)
              (uri "https://IdentityProvider.com/SAML/SLO/SOAP")
              Nothing [] []
            ,Endpoint
              (Identified BindingHTTPRedirect)
              (uri "https://IdentityProvider.com/SAML/SLO/Browser")
              (Just $ uri "https://IdentityProvider.com/SAML/SLO/Response")
              [] []]
            []
            [Identified NameIDFormatX509
            ,Identified NameIDFormatPersistent
            ,Identified NameIDFormatTransient])
          True
          (Endpoint
            (Identified BindingHTTPRedirect)
            (uri "https://IdentityProvider.com/SAML/SSO/Browser")
            Nothing [] []
          :| [Endpoint
            (Identified BindingHTTPPOST)
            (uri "https://IdentityProvider.com/SAML/SSO/Browser")
            Nothing [] []])
          [] [] []
          [ SAML.Attribute
            "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
            (Identified AttributeNameFormatURI)
            (Just "eduPersonPrincipalName")
            [] []
          , SAML.Attribute
            "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
            (Identified AttributeNameFormatURI)
            (Just "eduPersonAffiliation")
            []
            [ [HXT.mkText "member"]
            , [HXT.mkText "student"]
            , [HXT.mkText "faculty"]
            , [HXT.mkText "employee"]
            , [HXT.mkText "staff"]
            ]]
        :| AttributeAuthorityDescriptor
          (RoleDescriptor
            Nothing Nothing Nothing
            [uri $ namespaceURI SAMLP.ns]
            Nothing [] Nothing
            (Extensions [])
            [KeyDescriptor
              KeyTypeSigning
              (DS.KeyInfo
                Nothing
                (DS.KeyName "IdentityProvider.com AA Key"
                :| []))
              []]
            Nothing [])
          (Endpoint
            (Identified BindingSOAP)
            (uri "https://IdentityProvider.com/SAML/AA/SOAP")
            Nothing [] []
          :| [])
          [Endpoint
            (Identified BindingURI)
            (uri "https://IdentityProvider.com/SAML/AA/URI")
            Nothing [] []]
          [Identified NameIDFormatX509
          ,Identified NameIDFormatPersistent
          ,Identified NameIDFormatTransient]
          []
          [ SAML.Attribute
            "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
            (Identified AttributeNameFormatURI)
            (Just "eduPersonPrincipalName")
            [] []
          , SAML.Attribute
            "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
            (Identified AttributeNameFormatURI)
            (Just "eduPersonAffiliation")
            []
            [ [HXT.mkText "member"]
            , [HXT.mkText "student"]
            , [HXT.mkText "faculty"]
            , [HXT.mkText "employee"]
            , [HXT.mkText "staff"]
            ]]
        : [])
      (Just $ Organization
        []
        (Extensions [])
        (Localized "en" "Identity Providers R US" :| [])
        (Localized "en" "Identity Providers R US, a Division of Lerxst Corp." :| [])
        (Localized "en" (uri "https://IdentityProvider.com") :| []))
      []
      []

  , testXML "test/Metadata/metadata-sp.xml" $
    EntityDescriptor
      (uri "https://ServiceProvider.com/SAML")
      Nothing Nothing Nothing [] Nothing
      (Extensions [])
      (Descriptors $
        SPSSODescriptor
          (RoleDescriptor
            Nothing Nothing Nothing
            [uri $ namespaceURI SAMLP.ns]
            Nothing [] Nothing
            (Extensions [])
            [ KeyDescriptor
              KeyTypeSigning
              (DS.KeyInfo
                Nothing
                (DS.KeyName "ServiceProvider.com SSO Key"
                :| []))
              []
            , KeyDescriptor
              KeyTypeEncryption
              (DS.KeyInfo
                Nothing
                (DS.KeyName "ServiceProvider.com Encrypt Key"
                :| []))
              [XEnc.EncryptionMethod
                (Identified XEnc.KeyTransportRSA1_5)
                Nothing Nothing Nothing []]
            ]
            Nothing
            [])
          (SSODescriptor
            []
            [Endpoint
              (Identified BindingSOAP)
              (uri "https://ServiceProvider.com/SAML/SLO/SOAP")
              Nothing [] []
            ,Endpoint
              (Identified BindingHTTPRedirect)
              (uri "https://ServiceProvider.com/SAML/SLO/Browser")
              (Just $ uri "https://ServiceProvider.com/SAML/SLO/Response")
              [] []]
            []
            [Identified NameIDFormatTransient])
          True
          False
          (IndexedEndpoint
            (Endpoint
              (Identified BindingHTTPArtifact)
              (uri "https://ServiceProvider.com/SAML/SSO/Artifact")
              Nothing [] [])
            0
            True
          :| IndexedEndpoint
            (Endpoint
              (Identified BindingHTTPPOST)
              (uri "https://ServiceProvider.com/SAML/SSO/POST")
              Nothing [] [])
            1
            False
          : [])
          [ AttributeConsumingService
            0
            False
            (Localized "en" "Academic Journals R US" :| [])
            []
            (RequestedAttribute
              (SAML.Attribute
              "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
              (Identified AttributeNameFormatURI)
              (Just "eduPersonEntitlement")
              []
              [ [HXT.mkText "https://ServiceProvider.com/entitlements/123456789"]
              ])
              False
            :| [])
          ]
        :| [])
      (Just $ Organization
        []
        (Extensions [])
        (Localized "en" "Academic Journals R US" :| [])
        (Localized "en" "Academic Journals R US, a Division of Dirk Corp." :| [])
        (Localized "en" (uri "https://ServiceProvider.com") :| []))
      [] []

  , testXML "test/Metadata/metadata-osf.xml" $
    EntityDescriptor
      (uri "https://accounts.osf.io/shibboleth")
      (Just "_d1a16315f5a36fc0a7d997a1a71a77edd110a396")
      Nothing Nothing [] Nothing
      (Extensions $
        let alg t a =
              HXT.mkElement (HXT.mkQName "alg" (t ++ "Method") "urn:oasis:names:tc:SAML:metadata:algsupport")
                [HXT.mkAttr (HXT.mkName "Algorithm") [HXT.mkText $ show $ identifier a]]
                [] in
      [ alg "Digest" DS.DigestSHA512
      , alg "Digest" DS.DigestSHA384
      , alg "Digest" DS.DigestSHA256
      , alg "Digest" DS.DigestSHA224
      , alg "Digest" DS.DigestSHA1
      , alg "Signing" DS.SignatureECDSA_SHA512
      , alg "Signing" DS.SignatureECDSA_SHA384
      , alg "Signing" DS.SignatureECDSA_SHA256
      , alg "Signing" DS.SignatureECDSA_SHA224
      , alg "Signing" DS.SignatureRSA_SHA512
      , alg "Signing" DS.SignatureRSA_SHA384
      , alg "Signing" DS.SignatureRSA_SHA256
      , alg "Signing" DS.SignatureDSA_SHA256
      , alg "Signing" DS.SignatureECDSA_SHA1
      , alg "Signing" DS.SignatureRSA_SHA1
      , alg "Signing" DS.SignatureDSA_SHA1
      ])
      (Descriptors
        (SPSSODescriptor
          (RoleDescriptor 
            Nothing Nothing Nothing
            [ uri "urn:oasis:names:tc:SAML:2.0:protocol"
            , uri "urn:oasis:names:tc:SAML:1.1:protocol"
            , uri "urn:oasis:names:tc:SAML:1.0:protocol"
            ]
            Nothing [] Nothing
            (Extensions [
              pickleElem (xpTrimElemNS (Namespace "init" "urn:oasis:names:tc:SAML:profiles:SSO:request-init") "RequestInitiator" XP.xpickle) $
              Endpoint
                (Unidentified $ uri "urn:oasis:names:tc:SAML:profiles:SSO:request-init")
                (uri "https://accounts.osf.io/Shibboleth.sso/Login")
                Nothing [] []
            ])
            [ KeyDescriptor 
              KeyTypeBoth
              (DS.KeyInfo 
                Nothing
                (DS.KeyName "f04f8d134cd2"
                :| DS.X509Data 
                  (DS.X509SubjectName "CN=f04f8d134cd2"
                  :| DS.X509Certificate "0\130\STX\235\&0\130\SOH\211\160\ETX\STX\SOH\STX\STX\t\NUL\154\132\171@\222\174iQ0\r\ACK\t*\134H\134\247\r\SOH\SOH\ENQ\ENQ\NUL0\ETB1\NAK0\DC3\ACK\ETXU\EOT\ETX\DC3\ff04f8d134cd20\RS\ETB\r151229001137Z\ETB\r251226001137Z0\ETB1\NAK0\DC3\ACK\ETXU\EOT\ETX\DC3\ff04f8d134cd20\130\SOH\"0\r\ACK\t*\134H\134\247\r\SOH\SOH\SOH\ENQ\NUL\ETX\130\SOH\SI\NUL0\130\SOH\n\STX\130\SOH\SOH\NUL\221{\CAN\250\180^\163X\171u\163+\214/\160\220W%8\164O\166\157\&7H\139\242\221\153\148\173\138\226\159n\159\176%~Z\179\144\137\150\218\159\225t\239\171\255&\183\&5\170\231\147\&7W\ETB[\171+\227\147\144\242\154)hvx\ACK\158\158\229\187\157H|{g>Y\166tJ\232+\165\\\251\250\218\177\129\129\244\CANx\r\b\223\245\182k\151\ENQE,xz\231\210)\ESC\150=\134\241~\171]\163\131R?5\210\ETX\245\157\253\131j\152q\193(\195\244\254\186\229\CAN\136\174\173\206B}w\227\&9\166_q\176J\193\r\219\227\191\255\SI\SI$2\153\191\231\160f\tbni\USn)\183\rVKF\221\184\SYNBH\216\178\&8\236\&9d3\RS{\STXQK\ETBa\244\234?bJ\178\207n:\203\165\234\203\213\243\159M\241\194\200D\\V@\140\147\186\190\130\218\bwbe\132^\224\217\247N\241Zw\197\134\234\130\ENQ\183\145G\STX\ETX\SOH\NUL\SOH\163:080\ETB\ACK\ETXU\GS\DC1\EOT\DLE0\SO\130\ff04f8d134cd20\GS\ACK\ETXU\GS\SO\EOT\SYN\EOT\DC4mz3\128Z\139\f\179>\185\134\&1\213\250J\165\233\251\203x0\r\ACK\t*\134H\134\247\r\SOH\SOH\ENQ\ENQ\NUL\ETX\130\SOH\SOH\NUL#\"\175\190\138\&9\237|Z\135L\157\160\&7\243\138\243\175\241\228Ui\228\223\&1 \SYN\188\170\192\155-\186\&7\221\250\167\RS\142=\193\218h\224x\246L6\155\&8f\176r\217\&8<\195&\DC38A\149\247\157y\156\132x\224_\DC3  &m\208\139\b6\224\SUBLH\254\218\207\US2\EOT\SI\SIg\236*\187\244^^FS\198\203C\179\157f\v\SI\129%\148)\DC2\211\171\200\237\237y\ESC\132c\255\DLE\153\ENQ\186\153~(\132\255\USm\200~j\153h1\207\138\173\249)\236\223\173f5\180:H\ETX\144\158\212\ETB\151\b\133f\208\ENQ\178[\DC4\131\232\229}\NUL\fAPf\ETX2|FX\196\GS\154_F\EOT\SO\201\&2\177\223\186\166\ENQd\141\171\233\NULUHd\201S\128\EOT|\246\EM\140O\202<fL\\x\183h\246o\230\166\STXrj]\196Z^\132)\206\&8e|+,T\204\219\251;\158T8\DC3\ACK\197\DC1\190\162{Y\250"
                  : [])
                : []))
              [ XEnc.EncryptionMethod 
                (Identified XEnc.BlockEncryptionAES128GCM)
                Nothing Nothing Nothing []
              , XEnc.EncryptionMethod 
                (Identified XEnc.BlockEncryptionAES192GCM)
                Nothing Nothing Nothing []
              , XEnc.EncryptionMethod 
                (Identified XEnc.BlockEncryptionAES256GCM)
                Nothing Nothing Nothing []
              , XEnc.EncryptionMethod 
                (Identified XEnc.BlockEncryptionAES128)
                Nothing Nothing Nothing []
              , XEnc.EncryptionMethod 
                (Identified XEnc.BlockEncryptionAES192)
                Nothing Nothing Nothing []
              , XEnc.EncryptionMethod 
                (Identified XEnc.BlockEncryptionAES256)
                Nothing Nothing Nothing []
              , XEnc.EncryptionMethod 
                (Identified XEnc.BlockEncryptionTripleDES)
                Nothing Nothing Nothing []
              , XEnc.EncryptionMethod 
                (Identified XEnc.KeyTransportRSAOAEP)
                Nothing Nothing Nothing []
              , XEnc.EncryptionMethod 
                (Identified XEnc.KeyTransportRSAOAEPMGF1P)
                Nothing Nothing Nothing []
              ] 
            ]
            Nothing [])
          (SSODescriptor 
            [IndexedEndpoint 
              (Endpoint 
                (Identified BindingSOAP)
                (uri "https://accounts.osf.io/Shibboleth.sso/Artifact/SOAP")
                Nothing [] [])
              1
              False]
            [ Endpoint 
              (Identified BindingSOAP)
              (uri "https://accounts.osf.io/Shibboleth.sso/SLO/SOAP")
              Nothing [] []
            , Endpoint 
              (Identified BindingHTTPRedirect)
              (uri "https://accounts.osf.io/Shibboleth.sso/SLO/Redirect")
              Nothing [] []
            , Endpoint 
              (Identified BindingHTTPPOST)
              (uri "https://accounts.osf.io/Shibboleth.sso/SLO/POST")
              Nothing [] []
            , Endpoint 
              (Identified BindingHTTPArtifact)
              (uri "https://accounts.osf.io/Shibboleth.sso/SLO/Artifact")
              Nothing [] []
            ]
            [] [])
          False False
          (IndexedEndpoint 
            (Endpoint 
              (Identified BindingHTTPPOST)
              (uri "https://accounts.osf.io/Shibboleth.sso/SAML2/POST")
              Nothing [] [])
            1
            False
          :| IndexedEndpoint 
            (Endpoint 
              (Unidentified $ uri "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign")
              (uri "https://accounts.osf.io/Shibboleth.sso/SAML2/POST-SimpleSign")
              Nothing [] [])
            2
            False
          : IndexedEndpoint 
            (Endpoint 
              (Identified BindingHTTPArtifact)
              (uri "https://accounts.osf.io/Shibboleth.sso/SAML2/Artifact")
              Nothing [] [])
            3
            False
          : IndexedEndpoint 
            (Endpoint 
              (Identified BindingPAOS)
              (uri "https://accounts.osf.io/Shibboleth.sso/SAML2/ECP")
              Nothing [] [])
            4
            False
          : IndexedEndpoint 
            (Endpoint 
              (Unidentified $ uri "urn:oasis:names:tc:SAML:1.0:profiles:browser-post")
              (uri "https://accounts.osf.io/Shibboleth.sso/SAML/POST")
              Nothing [] [])
            5
            False
          : IndexedEndpoint 
            (Endpoint 
              (Unidentified $ uri "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01")
              (uri "https://accounts.osf.io/Shibboleth.sso/SAML/Artifact")
              Nothing [] [])
            6
            False
          : [])
          []
        :| []))
      Nothing
      []
      []
  ]
