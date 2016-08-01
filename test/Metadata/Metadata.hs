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
import SAML2.Core.Versioning
import SAML2.Core.Namespaces
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
            [ samlURN SAML20 ["protocol"]
            , samlURN SAML11 ["protocol"]
            , samlURN SAML10 ["protocol"]
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
              (Unidentified $ samlURN SAML20 ["bindings", "HTTP-POST-SimpleSign"])
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
              (Unidentified $ samlURN SAML10 ["profiles", "browser-post"])
              (uri "https://accounts.osf.io/Shibboleth.sso/SAML/POST")
              Nothing [] [])
            5
            False
          : IndexedEndpoint 
            (Endpoint 
              (Unidentified $ samlURN SAML10 ["profiles", "artifact-01"])
              (uri "https://accounts.osf.io/Shibboleth.sso/SAML/Artifact")
              Nothing [] [])
            6
            False
          : [])
          []
        :| []))
      Nothing [] []

  , testXML "test/Metadata/metadata-nyu.xml" $
    EntityDescriptor
      (uri "urn:mace:incommon:nyu.edu")
      Nothing
      Nothing Nothing [] Nothing
      (Extensions [])
      (Descriptors
        (IDPSSODescriptor
          (RoleDescriptor 
            Nothing Nothing Nothing
            [ uri "urn:mace:shibboleth:1.0"
            , samlURN SAML11 ["protocol"]
            , samlURN SAML20 ["protocol"]
            ]
            Nothing [] Nothing
            (Extensions [
              HXT.mkElement (HXT.mkQName "shibmd" "Scope" "urn:mace:shibboleth:metadata:1.0")
                [HXT.mkAttr (HXT.mkName "regexp") [HXT.mkText "false"]]
                [HXT.mkText "nyu.edu"]
            ])
            [ KeyDescriptor 
              KeyTypeSigning
              (DS.KeyInfo 
                Nothing
                (DS.X509Data 
                  (DS.X509Certificate "0\130\ACKM0\130\ENQ5\160\ETX\STX\SOH\STX\STX\SOH|0\r\ACK\t*\134H\134\247\r\SOH\SOH\ENQ\ENQ\NUL0V1\v0\t\ACK\ETXU\EOT\ACK\DC3\STXUS1\FS0\SUB\ACK\ETXU\EOT\n\DC3\DC3InCommon Federation1)0'\ACK\ETXU\EOT\ETX\DC3 InCommon Certification Authority0\RS\ETB\r070116232303Z\ETB\r080116232303Z081\v0\t\ACK\ETXU\EOT\ACK\DC3\STXUS1\f0\n\ACK\ETXU\EOT\n\DC3\ETXNYU1\ESC0\EM\ACK\ETXU\EOT\ETX\DC3\DC2shibboleth.nyu.edu0\130\SOH\184\&0\130\SOH,\ACK\a*\134H\206\&8\EOT\SOH0\130\SOH\US\STX\129\129\NUL\253\DELS\129\GSu\DC2)R\223J\156.\236\228\231\246\DC1\183R<\239D\NUL\195\RS?\128\182Q&iE]@\"Q\251Y=\141X\250\191\197\245\186\&0\246\203\155Ul\215\129;\128\GS4o\242f`\183k\153P\165\164\159\159\232\EOT{\DLE\"\194O\187\169\215\254\183\198\ESC\248;W\231\198\168\166\NAK\SI\EOT\251\131\246\211\197\RS\195\STX5T\DC3Z\SYN\145\&2\246u\243\174+a\215*\239\242\"\ETX\EM\157\209H\SOH\199\STX\NAK\NUL\151`P\143\NAK#\v\204\178\146\185\130\162\235\132\v\240X\FS\245\STX\129\129\NUL\247\225\160\133\214\155=\222\203\188\171\\6\184W\185y\148\175\187\250:\234\130\249WL\v=\a\130gQYW\142\186\212YO\230q\a\DLE\129\128\180I\SYNq#\232L(\SYN\DC3\183\207\t2\140\200\166\225<\SYNz\139T|\141(\224\163\174\RS+\179\166u\145n\163\DEL\v\250!5b\241\251bz\SOH$;\204\164\241\190\168Q\144\137\168\131\223\225Z\229\159\ACK\146\139f^\128{U%d\SOHL;\254\207I*\ETX\129\133\NUL\STX\129\129\NUL\228b\190y]\216\187'\219M\226W\158\165x\141?\142s>\215\b\190\DC3\153\230\NUL\165\203\128\254\209\187\189\DC4J\151c\178\163\221\213\t\238\198\199\ETX\128\ETB*vj:\177w0\DEL\200\US\204s?4\CANB\243\253A:\190@=\tm\245\230\SOH\208\251\&5\136\153F\207\197\218y\189\250\RS\215\ACK{Ze\195D\222~\225 \233\182R\129>\198Aj\208\t\132\CAN\201:E\139\255==w$]\131\230\CAN]\193\163\130\STX\172\&0\130\STX\168\&0\SO\ACK\ETXU\GS\SI\SOH\SOH\255\EOT\EOT\ETX\STX\ENQ\160\&0\f\ACK\ETXU\GS\DC3\SOH\SOH\255\EOT\STX0\NUL0\GS\ACK\ETXU\GS%\EOT\SYN0\DC4\ACK\b+\ACK\SOH\ENQ\ENQ\a\ETX\SOH\ACK\b+\ACK\SOH\ENQ\ENQ\a\ETX\STX0\GS\ACK\ETXU\GS\SO\EOT\SYN\EOT\DC4\137\209\220M\178,{S\132\DEL\241qy\252F3\192\SYNz80~\ACK\ETXU\GS#\EOTw0u\128\DC4\147-\200a\CAN\173c\227\155e\179\157\221\141\147\186\231\202cE\161Z\164X0V1\v0\t\ACK\ETXU\EOT\ACK\DC3\STXUS1\FS0\SUB\ACK\ETXU\EOT\n\DC3\DC3InCommon Federation1)0'\ACK\ETXU\EOT\ETX\DC3 InCommon Certification Authority\130\SOH\NUL0\129\186\ACK\b+\ACK\SOH\ENQ\ENQ\a\SOH\SOH\EOT\129\173\&0\129\170\&0\129\167\ACK\b+\ACK\SOH\ENQ\ENQ\a0\STX\134\129\154http://incommonca1.incommonfederation.org/bridge/certs/ca-certs.p7b\n\t\tCA Issuers - URI:http://incommonca2.incommonfederation.org/bridge/certs/ca-certs.p7b0\129\141\ACK\ETXU\GS\US\EOT\129\133\&0\129\130\&0?\160=\160;\134\&9http://incommoncrl1.incommonfederation.org/crl/eecrls.crl0?\160=\160;\134\&9http://incommoncrl2.incommonfederation.org/crl/eecrls.crl0^\ACK\ETXU\GS \EOTW0U0S\ACK\v+\ACK\SOH\EOT\SOH\174#\SOH\EOT\SOH\SOH0D0B\ACK\b+\ACK\SOH\ENQ\ENQ\a\STX\SOH\SYN6http://incommonca.incommonfederation.org/practices.pdf0\GS\ACK\ETXU\GS\DC1\EOT\SYN0\DC4\130\DC2shibboleth.nyu.edu0\r\ACK\t*\134H\134\247\r\SOH\SOH\ENQ\ENQ\NUL\ETX\130\SOH\SOH\NUL\173N\237\243\NAK\n\232\242\135\t?\216\223\156\151\187-\f/\v\239\SYN\210\DEL\192\196\153\228\161\167@Y{\203\234\197\148\252Z\DC3\131\143)\165\238\128\224\177fg\196\153\"\175\251\&5\234:I\251\212\146\DC4\254;\217\128\174x\217'\165\192\187\247\a\209\240\255(\DLE$R\EM\EOTBYmK-OO`)\162\191\237\139m\bW\172\156\\\147\220\224\ENQA\135\181\255\152\170Y\235\142\130Zq\239\162#\212\168\240\"\206<d\199D\230\162\198\139\251b\NAK\ETX\207\213waW\167\231\t,\152(\\\196\131y;6\157\248\253\211\232M\DC3\145\132\246\200Q\DEL\169I\150\151U\226u\\\239\139\186\DC3Dp\160'\191\239\165+\186OU\205\200\139J\"p\DC2?\228\184S\223\131\221\236\212\174p\215\FS\172\150k]\197\135z\GS\177\&14j\149H\238Z\169\152\206\166\129y;\242\169\223\211W\214+\244\243(\203Pk\172\215E%+\144q"
                  :| [])
                :| []))
              [] 
            , KeyDescriptor 
              KeyTypeSigning
              (DS.KeyInfo 
                Nothing
                (DS.X509Data 
                  (DS.X509Certificate "0\130\EOT\232\&0\130\ETX\208\160\ETX\STX\SOH\STX\STX\t\NUL\141\149\236\&9\165\128\180\&50\r\ACK\t*\134H\134\247\r\SOH\SOH\ENQ\ENQ\NUL0\129\168\&1\v0\t\ACK\ETXU\EOT\ACK\DC3\STXUS1\DC10\SI\ACK\ETXU\EOT\b\DC3\bNew York1\DC10\SI\ACK\ETXU\EOT\a\DC3\bNew York1\FS0\SUB\ACK\ETXU\EOT\n\DC3\DC3New York University1\f0\n\ACK\ETXU\EOT\v\DC3\ETXITS1\"0 \ACK\ETXU\EOT\ETX\DC3\EMurn:mace:incommon:nyu.edu1#0!\ACK\t*\134H\134\247\r\SOH\t\SOH\SYN\DC4idm.services@nyu.edu0\RS\ETB\r120810213516Z\ETB\r220808213516Z0\129\168\&1\v0\t\ACK\ETXU\EOT\ACK\DC3\STXUS1\DC10\SI\ACK\ETXU\EOT\b\DC3\bNew York1\DC10\SI\ACK\ETXU\EOT\a\DC3\bNew York1\FS0\SUB\ACK\ETXU\EOT\n\DC3\DC3New York University1\f0\n\ACK\ETXU\EOT\v\DC3\ETXITS1\"0 \ACK\ETXU\EOT\ETX\DC3\EMurn:mace:incommon:nyu.edu1#0!\ACK\t*\134H\134\247\r\SOH\t\SOH\SYN\DC4idm.services@nyu.edu0\130\SOH\"0\r\ACK\t*\134H\134\247\r\SOH\SOH\SOH\ENQ\NUL\ETX\130\SOH\SI\NUL0\130\SOH\n\STX\130\SOH\SOH\NUL\223o\134\232\180\242Sp\195\194,7\167\204z\150\NUL\226Ezu\ACK\DLE\STX\247\221\DC3\179\ETX\175;o\189\197\131\189\133\158Xv>\158\199\&6\SYN\193\223\231\DLE\142\196\SO\SO+c\NAK\213\NAKB\ENQ\252\DLE\ETX\247\196\198@\CAN\165\&63\253\EM\EM\249\198\162H\249\162%4\243H\162\235\&3\179\DLE5\STX\146\233Q\228%\186\167\233\160v\128\152^\205\219\246\184\176\155U\249\166\168\191\225\150\194(\255\138\233\&8\146\EOT\225\150\198\208\172\ACK\158\230XWI\149e\DC3\233\173\213E\218\CAN\153E\DLE\DLE\226_\173<\147\240%\180vM\ETX\EM:\SYN{h\247\181\172FO\207D\221P:\195\145\164\181\STX\185\179\EMe\DLE\ENQP\219w\226\&1\218.\f\vk\226\NUL\205\188\228\176\181\133.\SI\b\DEL>\153\DEL\148\ETX0\141O\157\191O)6\226Q\245\218\197\141\131\&4\140\170\">\193\189\SOH\209\&0\144T\134A\189\b\a\\-\243\236\NULy0\151 \163+\STX\ETX\SOH\NUL\SOH\163\130\SOH\DC10\130\SOH\r0\GS\ACK\ETXU\GS\SO\EOT\SYN\EOT\DC4\149\228.\172J\129\198\195\135\170\DC2\253\210\DLE\162X\194\136\191\GS0\129\221\ACK\ETXU\GS#\EOT\129\213\&0\129\210\128\DC4\149\228.\172J\129\198\195\135\170\DC2\253\210\DLE\162X\194\136\191\GS\161\129\174\164\129\171\&0\129\168\&1\v0\t\ACK\ETXU\EOT\ACK\DC3\STXUS1\DC10\SI\ACK\ETXU\EOT\b\DC3\bNew York1\DC10\SI\ACK\ETXU\EOT\a\DC3\bNew York1\FS0\SUB\ACK\ETXU\EOT\n\DC3\DC3New York University1\f0\n\ACK\ETXU\EOT\v\DC3\ETXITS1\"0 \ACK\ETXU\EOT\ETX\DC3\EMurn:mace:incommon:nyu.edu1#0!\ACK\t*\134H\134\247\r\SOH\t\SOH\SYN\DC4idm.services@nyu.edu\130\t\NUL\141\149\236\&9\165\128\180\&50\f\ACK\ETXU\GS\DC3\EOT\ENQ0\ETX\SOH\SOH\255\&0\r\ACK\t*\134H\134\247\r\SOH\SOH\ENQ\ENQ\NUL\ETX\130\SOH\SOH\NUL\194\239\SO\EM\206O\234\130\147a\153\231\180\221LF:,e\SYN\DEL\148i\142\144\DC1\216\193 \237\206\222m\180\132E\139\167\131\218\249\&0o\177)l\NAKd!\213i_\158\ACK_\128\175\204\141\156\164v\r>ll\DC1O\210Lq\150\224\247\ETB\174\206s\130\DC1\233\238L\194m\SO\184\170\187\&4\229\&7\169\172\217\233\158\150\NUL^~$\SO\164\&0\191\134\197\247\RS\189&\137\&8\NAK\171\172[\222dqR\147\DC2DP\DLE\170\t&W\141\&7}\SI\164w\193\\\177,\181\142\&4\185\\\188\ETB\136\GS\244\\\219\128\213Q4\RSU\172\226^\ETXWQ\191\219\130\\\212z\251\137L\162d\199\217\149\153\EOT\186;\187<\234\230\198\213\&4E\157\&4\SI(\172\183;\135\131i%\236yS\ENQ\251N\179\193C\196\205\236\170+re'.\181\t\175\&1\238\141\v/\247\157!r\FS$\ENQ=\251\186\233\188\156\178\198\ACKG\238\CAN\190\216\194e\NAK\SUB\179\153\DC2"
                  :| [])
                :| []))
              [] 
            ]
            Nothing [])
          (SSODescriptor 
            [] [] [] [])
          False
          (Endpoint 
            (Unidentified $ uri "urn:mace:shibboleth:1.0:profiles:AuthnRequest")
            (uri "https://shibboleth.nyu.edu/idp/profile/Shibboleth/SSO")
            Nothing [] []
          :| Endpoint 
            (Identified BindingHTTPRedirect)
            (uri "https://shibboleth.nyu.edu/idp/profile/SAML2/Redirect/SSO")
            Nothing [] []
          : Endpoint 
            (Identified BindingHTTPPOST)
            (uri "https://shibboleth.nyu.edu/idp/profile/SAML2/POST/SSO")
            Nothing [] []
          : [])
          []
          []
          []
          []
        :| []))
      (Just $ Organization
        []
        (Extensions [])
        (Localized "en" "New York University" :| [])
        (Localized "en" "New York University" :| [])
        (Localized "en" (uri "http://www.nyu.edu/") :| []))
      [ ContactPerson
        ContactTypeTechnical
        []
        (Extensions [])
        Nothing
        (Just "Yavor Yanakiev")
        Nothing
        [uri "yy27@nyu.edu"]
        []
      , ContactPerson
        ContactTypeTechnical
        []
        (Extensions [])
        Nothing
        (Just "Tracy Edappara")
        Nothing
        [uri "tte3@nyu.edu"]
        []
      , ContactPerson
        ContactTypeAdministrative
        []
        (Extensions [])
        Nothing
        (Just "Gary Chapman")
        Nothing
        [uri "gwc1@nyu.edu"]
        []
      ]
      []
  ]
