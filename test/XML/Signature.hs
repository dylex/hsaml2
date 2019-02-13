{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ViewPatterns #-}
module XML.Signature (tests) where

import Control.Exception (SomeException, try)
import Control.Monad
import Data.Either (isLeft)
import Data.List (isInfixOf)
import Data.List.NonEmpty (NonEmpty(..))
import Data.Time
import System.IO.Unsafe (unsafePerformIO)

import qualified Crypto.PubKey.DSA as DSA
import qualified Data.ByteString.Base64.Lazy as EL
import qualified Data.ByteString.Lazy as BSL
import qualified Data.X509 as X509
import qualified Test.HUnit as U
import qualified Text.XML.HXT.DOM.QualifiedName as HXT
import qualified Text.XML.HXT.DOM.XmlNode as HXT

import SAML2.Core.Protocols
import SAML2.Core.Versioning
import SAML2.Core.Signature
import SAML2.Core.Identifiers
import SAML2.XML
import SAML2.XML.Canonical
import SAML2.XML.Signature

import XML

tests :: U.Test
tests = U.test [serializationTests, signVerifyTests, verifyTests]


----------------------------------------------------------------------
-- serialization roundtrips

serializationTests :: U.Test
serializationTests = U.test
  [ testXML "test/XML/signature-example.xml" $
    Signature (Just "MyFirstSignature")
      (SignedInfo Nothing
        (CanonicalizationMethod
          (Identified (CanonicalXML10 False))
          Nothing
          [])
        (SignatureMethod
          (Identified SignatureDSA_SHA1)
          Nothing
          [])
        (Reference Nothing
          (Just $ uri "http://www.w3.org/TR/xml-stylesheet/")
          Nothing
          (Just $ Transforms $
            Transform
              (Identified TransformBase64)
              Nothing
              []
            :| [])
          (DigestMethod
            (Identified DigestSHA1)
            [])
          "\143\169p\199z\239\DLE\243\180\188\171L\186\158\rm\229n\242y"
        :| Reference Nothing
          (Just $ uri "http://www.w3.org/TR/REC-xml-names/")
          Nothing
          (Just $ Transforms $
            Transform
              (Identified TransformBase64)
              Nothing
              []
            :| [])
          (DigestMethod
            (Identified DigestSHA1)
            [])
          "R\181\203\f\176H\181\174\172\146\133y\252\SI\DLE\223\193\132\195\142"
        : []))
      (SignatureValue Nothing
        "0-\STX\DC4Z\213.\212e\144\199\&7\r\170'\224\SUB\170\158HB:Q\SUB\STX\NAK\NUL\147\202G\214$M+\234\181#\235\"\176\&4\243\217\&1D\NUL\177")
      (Just $ KeyInfo Nothing $
        KeyInfoKeyValue (DSAKeyValue
          (Just (4227,4467856506880))
          (Just 0)
          0
          Nothing
          Nothing)
        :| [])
      [Object Nothing
        Nothing
        Nothing
        [ObjectSignatureProperties $ SignatureProperties Nothing
          (SignatureProperty Nothing
            (uri "#MyFirstSignature")
            (HXT.mkElement (HXT.mkQName "ts" "timestamp" "http://www.example.org/rfc/rfcxxxx.txt")
              []
              [HXT.mkText "\n           this is a test of the mixed content model"]
            :| [])
          :| [])]]

  , testXML "http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/signature-example-rsa.xml" $
    Signature Nothing
      (SignedInfo Nothing
        (CanonicalizationMethod
          (Identified (CanonicalXML10 False))
          Nothing
          [])
        (SignatureMethod
          (Identified SignatureRSA_SHA1)
          Nothing
          [])
        (Reference Nothing
          (Just $ uri "http://www.w3.org/TR/xml-stylesheet")
          Nothing
          Nothing
          (DigestMethod
            (Identified DigestSHA1)
            [])
          "\235Cof\251]L\US\187RyK\167\241\246\226\158\225\225\187"
        :| []))
      (SignatureValue Nothing
        "\142\228\185F\DC2|\243\138\168\NAK\US\US\149U\221\254\182\235H5F\159\141\STXj\152\SOH\238\167\144\137?\171\175C^\144D:\EOTxT\ETX\199S\223\224BL\NAK\DLE#GA\142Y\165\246\\3\DLE\213\239K\205\243D@\163\205v\204E5-U\152\143dm\169\168\163\231/f\DC4\220\SIz\227\149\STX\141\&5\212\250\&8\ENQ\186k\251\147\191!\137\224\ACK\SI3\\\139\227\208\244\164f\155\255\226q>\201i\140\237\130\222")
      (Just $ KeyInfo Nothing $
        KeyInfoKeyValue (RSAKeyValue
          129320787110389946406925163824095500161767249273623083115363317842079233133623467127773858023148958966585889333894288698085674111884585270272937137414571531865090153762072690670922714784242933462808045060688046441910524319219807614054721975863956765214954333806674482022007523948700289932875920496009317903247
          65537)
        :| X509Data
          (X509SubjectName "\n        CN=Merlin Hughes,O=Baltimore Technologies\\, Ltd.,ST=Dublin,C=IE\n      "
          :| X509IssuerSerial
            "\n          CN=Test RSA CA,O=Baltimore Technologies\\, Ltd.,ST=Dublin,C=IE\n        "
            970849928
          : X509Certificate (either error id $ X509.decodeSignedObject
            "0\130\STXx0\130\SOH\225\160\ETX\STX\SOH\STX\STX\EOT9\221\254\136\&0\r\ACK\t*\134H\134\247\r\SOH\SOH\EOT\ENQ\NUL0[1\v0\t\ACK\ETXU\EOT\ACK\DC3\STXIE1\SI0\r\ACK\ETXU\EOT\b\DC3\ACKDublin1%0#\ACK\ETXU\EOT\n\DC3\FSBaltimore Technologies, Ltd.1\DC40\DC2\ACK\ETXU\EOT\ETX\DC3\vTest RSA CA0\RS\ETB\r001006163207Z\ETB\r011006163204Z0]1\v0\t\ACK\ETXU\EOT\ACK\DC3\STXIE1\SI0\r\ACK\ETXU\EOT\b\DC3\ACKDublin1%0#\ACK\ETXU\EOT\n\DC3\FSBaltimore Technologies, Ltd.1\SYN0\DC4\ACK\ETXU\EOT\ETX\DC3\rMerlin Hughes0\129\159\&0\r\ACK\t*\134H\134\247\r\SOH\SOH\SOH\ENQ\NUL\ETX\129\141\NUL0\129\137\STX\129\129\NUL\184(\174\146\152\SOh\233\171\171W\207Q1\247\b\ENQ\241\184Y\143\142\201\146\226\&9\211+\SUB\239\211\rI)\197\237'c7jF\149\213\223\228j\187\201\150g\154\163m#7/k\251\251\202\194&\227\&3\190\197\251v\200\145\227\EOT\SUB`\bRq\\\136\153\DC1\250(N\237\190\FSN\230'\DC2/1\RS\219\184\136\201\250\CAN\224\193\160L\234\NAK\ACK\GSw\202x\190\182A\178\251\&8\226t\235K\202\178\202\SYN\218\235\143\STX\ETX\SOH\NUL\SOH\163G0E0\RS\ACK\ETXU\GS\DC1\EOT\ETB0\NAK\129\DC3merlin@baltimore.ie0\SO\ACK\ETXU\GS\SI\SOH\SOH\255\EOT\EOT\ETX\STX\a\128\&0\DC3\ACK\ETXU\GS#\EOT\f0\n\128\bI\224\173\146\NAK\130\237\&70\r\ACK\t*\134H\134\247\r\SOH\SOH\EOT\ENQ\NUL\ETX\129\129\NULrn\224\149j\253i\215+j*\169\242\214\169\235\&9\188s\173}\DEL\217\132(\197\200\&3!\206\201H\241\169\186\218\ACK^w\ACK} \134H\194SQ2\241\ETX@\GS\179v\207\222\DLE\EM\200\SOH\ETX\229\255$K\b\179\159fv\192\240\245\235lS\249\138\v7\169\ENQ\146p\NAK#eX\226\147\190<\GSM\172QVNk\221\FS\210be\218\242l\253\FS2-n\255\184 \US\v\242?\147\220F\175\183\231z\130\SYN")
          : [])
        : [])
      []

  , testXML "http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/signature-example-dsa.xml" $
    Signature Nothing
      (SignedInfo Nothing
        (CanonicalizationMethod
          (Identified (CanonicalXML10 False))
          Nothing
          [])
        (SignatureMethod
          (Identified SignatureDSA_SHA1)
          Nothing
          [])
        (Reference Nothing
          (Just $ uri "http://www.w3.org/TR/xml-stylesheet")
          Nothing
          Nothing
          (DigestMethod
            (Identified DigestSHA1)
            [])
          "\235Cof\251]L\US\187RyK\167\241\246\226\158\225\225\187"
        :| []))
      (SignatureValue Nothing
        "\169@\ETX\f\193\217\147'\155\189\ETBK\179\238\131\191\180o\128\194\209\149F\131\a\132=\202\DELW\160\144;\245\173\188\243g\223N")
      (Just $ KeyInfo Nothing $
        KeyInfoKeyValue (DSAKeyValue
          (Just (153189639877411708224318232157362603672344144516811966787300053511761023886224186320604641484819218412604307502181416378142369715493548254902826913797675909798516465379299499179683104783603344189053156355893057246996756239330536459114483648506158907550755189559705056134296533730500485771224694549017281352213, 1393672757286116725466646726891466679477132949611))
          (Just 35729760834794135337622213068423837828001418115741637960451705317746718553830652249599411519579460551833355506946575671195284376652749132624400687252979877843978133909425395446287975790304889073526084815938167334643701873370635770822329121239717107729346766305695485960113338821879352438123181471401687525574)
          80624726256040348115552042320696813500187275370942441977258669395023235020055564647117594451929708788598704081077890850726227289270230377442285367559774800853404089092381420228663316324808605521697655145608801533888071381819208887705771753016938104409283940243801509765453542091716518238707344493641683483917
          Nothing
          Nothing)
        :| X509Data
          (X509SubjectName "\n        CN=Merlin Hughes,O=Baltimore Technologies\\, Ltd.,ST=Dublin,C=IE\n      "
          :| X509IssuerSerial
            "\n          CN=Test DSA CA,O=Baltimore Technologies\\, Ltd.,ST=Dublin,C=IE\n        "
            970849936
          : X509Certificate (either error id $ X509.decodeSignedObject
            "0\130\ETX70\130\STX\245\160\ETX\STX\SOH\STX\STX\EOT9\221\254\144\&0\t\ACK\a*\134H\206\&8\EOT\ETX0[1\v0\t\ACK\ETXU\EOT\ACK\DC3\STXIE1\SI0\r\ACK\ETXU\EOT\b\DC3\ACKDublin1%0#\ACK\ETXU\EOT\n\DC3\FSBaltimore Technologies, Ltd.1\DC40\DC2\ACK\ETXU\EOT\ETX\DC3\vTest DSA CA0\RS\ETB\r001006163215Z\ETB\r011006163214Z0]1\v0\t\ACK\ETXU\EOT\ACK\DC3\STXIE1\SI0\r\ACK\ETXU\EOT\b\DC3\ACKDublin1%0#\ACK\ETXU\EOT\n\DC3\FSBaltimore Technologies, Ltd.1\SYN0\DC4\ACK\ETXU\EOT\ETX\DC3\rMerlin Hughes0\130\SOH\182\&0\130\SOH+\ACK\a*\134H\206\&8\EOT\SOH0\130\SOH\RS\STX\129\129\NUL\218&7\195N\182\176\&0w\252\&2%-c\158\ESC\223\184R\153\131gGr\169\EM=t\185MC\170\154\\\142\237:\184\221\"\EM\186\159\247\142\195\142@B\219\152J\158\172\164+}q\a\r\EOT\b\246\216\171\242\130\247\201 \133\215\246\196\144\174\232\US\SUB\168\159y+\216\221U\249I\221c\251=\fI\159\231\230\&3m\243\203\161\216-uH\n\151\234z\215M\143\245G\t(Y\DC3v\221&!:V\134\210\NAK\STX\NAK\NUL\244\RSr\164\182=\164\195\166\183\DLE\158L1\224\193\211Exk\STX\129\128\&2\225\128\150\167\129\213\172~\191#\182\248\235.n8e\238\145\241.\238;D\129\254\252\206v\SO1\DC2\ETX\210\140J\188\&3\177\140|\200\212vZ\138\SOH\202\177\&4\183\167\238\209Y\220+\181\n\242\137N\226\222\240\166\253\179\224\SOHP=\NAKB(\\(\210\168'\229\162\136\144\128\134\&2Z\209\203\205Z\189\189\187\192g\SYN\162\216q\222#\207\&2\209W\182\128\234+BH\181\162=G\204\220\214k\ENQ\132\205F(\198\ETX\129\132\NUL\STX\129\128r\208<`lk\182x \255\&2\149\190\161\SOy\249\240\153X\133\206\215'<\SYN\SI\148\155/\135\172\138#\136\131\155\175\US\158\158\f\139tk'\166\217\ETX(\ENQ\173B\DLE/\DC2\227W\227\137\182\STX@\DC2\218\&4\196\v>1\232n\171P\228HQ)?z\ETX\204$\206\178\179\162KP\240A\238(!\190\243VO\253\151\182\143\180\147\a[B\213\148\199pd\209M4\154*1\196\246e\240\143\173\251\216\189\r\163G0E0\RS\ACK\ETXU\GS\DC1\EOT\ETB0\NAK\129\DC3merlin@baltimore.ie0\SO\ACK\ETXU\GS\SI\SOH\SOH\255\EOT\EOT\ETX\STX\a\128\&0\DC3\ACK\ETXU\GS#\EOT\f0\n\128\bBY@m\n\193\SYN\207\&0\t\ACK\a*\134H\206\&8\EOT\ETX\ETX1\NUL0.\STX\NAK\NUL\174,\145a\ENQb\n\224\129\162@\242\246\NUL\193(\224\215o\138\STX\NAK\NUL\192t\232\239\ax\180Cp\244\176\n>IP\255\190\US\US_")
          : [])
        : [])
      []
  ]


----------------------------------------------------------------------
-- signing / verification

signVerifyTests :: U.Test
signVerifyTests = U.test
  [ U.TestCase $ do
      let req = somereq
      req' <- signSAMLProtocol privkey1 req
      let reqlbs = samlToXML req'
      req'' :: AuthnRequest <- verifySAMLProtocol reqlbs
      U.assertEqual "AuthnRequest with verifySAMLProtocol (no pubkeys)" req' req''

  , U.TestCase $ do
      let req = somereq
      req' <- signSAMLProtocol privkey1 req
      let reqdoc = samlToDoc' req'
      req'' :: AuthnRequest <- verifySAMLProtocol' pubkey1 reqdoc
      U.assertEqual "AuthnRequest with verifySAMLProtocol' (matching pubkeys)" req' req''

  , U.TestCase $ do
      let req = somereq
      req' <- signSAMLProtocol privkey1 req
      let reqdoc = samlToDoc' req'
      req'' :: Either SomeException AuthnRequest <- try $ verifySAMLProtocol' pubkey2 reqdoc
      U.assertBool "AuthnRequest with verifySAMLProtocol' (bad pubkeys): isLeft"
        $ isLeft req''
      U.assertBool "AuthnRequest with verifySAMLProtocol' (bad pubkeys): error message matches"
        $ "SignatureVerificationCryptoFailed" `isInfixOf` show req''
  ]

{-# NOINLINE keypair1 #-}
keypair1 :: (SigningKey, PublicKeys)
keypair1 = unsafePerformIO mkkeypair

{-# NOINLINE keypair2 #-}
keypair2 :: (SigningKey, PublicKeys)
keypair2 = unsafePerformIO mkkeypair

privkey1, _privkey2 :: SigningKey
pubkey1, pubkey2 :: PublicKeys
((privkey1, pubkey1), (_privkey2, pubkey2)) = (keypair1, keypair2)

mkkeypair :: IO (SigningKey, PublicKeys)
mkkeypair = do
  privnum <- DSA.generatePrivate params
  let pubnum = DSA.calculatePublic params privnum
      kp = DSA.KeyPair params pubnum privnum
  pure (SigningKeyDSA kp, PublicKeys (Just $ DSA.toPublicKey kp) Nothing)
  where
    params = DSA.Params
      { DSA.params_p = 13232376895198612407547930718267435757728527029623408872245156039757713029036368719146452186041204237350521785240337048752071462798273003935646236777459223
      , DSA.params_q = 857393771208094202104259627990318636601332086981
      , DSA.params_g = 5421644057436475141609648488325705128047428394380474376834667300766108262613900542681289080713724597310673074119355136085795982097390670890367185141189796
      }

somereq :: AuthnRequest
somereq = AuthnRequest
  { authnRequest = RequestAbstractType someprottype
  , authnRequestForceAuthn = False
  , authnRequestIsPassive = False
  , authnRequestAssertionConsumerService = AssertionConsumerServiceURL Nothing Nothing
  , authnRequestAssertionConsumingServiceIndex = Nothing
  , authnRequestProviderName = Nothing
  , authnRequestSubject = Nothing
  , authnRequestNameIDPolicy = Nothing
  , authnRequestConditions = Nothing
  , authnRequestRequestedAuthnContext = Nothing
  , authnRequestScoping = Nothing
  }

someprottype :: ProtocolType
someprottype = ProtocolType
  { protocolID = "wef"
  , protocolVersion = SAML20
  , protocolIssueInstant = someTime
  , protocolDestination = Nothing
  , protocolConsent = Identified ConsentUnspecified
  , protocolIssuer = Nothing
  , protocolSignature = Nothing
  , protocolExtensions = []
  , relayState = Nothing
  }

someTime :: UTCTime
Just someTime = parseTimeM True defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" "2013-03-18T03:28:54.1Z"

----------------------------------------------------------------------
-- some real-world responses and signature verification runs

data VerifyExample = VerifyExample
  BSL.ByteString              -- keyinfo from metadata of idp
  BSL.ByteString              -- signed response (in the base64 encoded form from the multipart body)
  String                      -- identifier of the sub-tree of which the signature is to be verified
  (Either SignatureError ())  -- expected result
  Int                         -- serial number
  deriving (Eq, Show)

verifyTests :: U.Test
verifyTests = U.test $ runVerifyExample <$> examples

runVerifyExample :: VerifyExample -> U.Test
runVerifyExample (VerifyExample keys xmltree refid want examplenumber) = U.TestCase $ do
  let keys'    = either (error . show) id $ parseKeyInfo keys
  let xmltree' = either (error . show) id $ (EL.decode >=> xmlToDocE) xmltree
  have <- verifySignature keys' refid xmltree'
  U.assertEqual ("verify example #" ++ show examplenumber) want have

parseKeyInfo :: BSL.ByteString -> Either String PublicKeys
parseKeyInfo = getCert >=> getKeys
  where
    getCert :: BSL.ByteString -> Either String X509.SignedCertificate
    getCert raw = case xmlToSAML @KeyInfo raw of
      (Right (keyInfoElements -> X509Data (X509Certificate cert :| []) :| [])) -> Right cert
      bad -> Left $ "unsupported: " ++ show bad

    getKeys :: X509.SignedCertificate -> Either String PublicKeys
    getKeys cert = do
      case X509.certPubKey . X509.signedObject $ X509.getSigned cert of
        X509.PubKeyDSA pk -> Right $ PublicKeys (Just pk) Nothing
        X509.PubKeyRSA pk -> Right $ PublicKeys Nothing (Just pk)
        bad -> Left $ "unsupported: " ++ show bad


examples :: [VerifyExample]
examples = zipWith ($) xs [1..]
  where xs :: [Int -> VerifyExample]
        xs =
          [ VerifyExample
            "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>MIIDBTCCAe2gAwIBAgIQev76BWqjWZxChmKkGqoAfDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE4MDIxODAwMDAwMFoXDTIwMDIxOTAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMgmGiRfLh6Fdi99XI2VA3XKHStWNRLEy5Aw/gxFxchnh2kPdk/bejFOs2swcx7yUWqxujjCNRsLBcWfaKUlTnrkY7i9x9noZlMrijgJy/Lk+HH5HX24PQCDf+twjnHHxZ9G6/8VLM2e5ZBeZm+t7M3vhuumEHG3UwloLF6cUeuPdW+exnOB1U1fHBIFOG8ns4SSIoq6zw5rdt0CSI6+l7b1DEjVvPLtJF+zyjlJ1Qp7NgBvAwdiPiRMU4l8IRVbuSVKoKYJoyJ4L3eXsjczoBSTJ6VjV2mygz96DC70MY3avccFrk7tCEC6ZlMRBfY1XPLyldT7tsR3EuzjecSa1M8CAwEAAaMhMB8wHQYDVR0OBBYEFIks1srixjpSLXeiR8zES5cTY6fBMA0GCSqGSIb3DQEBCwUAA4IBAQCKthfK4C31DMuDyQZVS3F7+4Evld3hjiwqu2uGDK+qFZas/D/eDunxsFpiwqC01RIMFFN8yvmMjHphLHiBHWxcBTS+tm7AhmAvWMdxO5lzJLS+UWAyPF5ICROe8Mu9iNJiO5JlCo0Wpui9RbB1C81Xhax1gWHK245ESL6k7YWvyMYWrGqr1NuQcNS0B/AIT1Nsj1WY7efMJQOmnMHkPUTWryVZlthijYyd7P2Gz6rY5a81DAFqhDNJl2pGIAE6HWtSzeUEh3jCsHEkoglKfm4VrGJEuXcALmfCMbdfTvtu4rlsaP2hQad+MG/KJFlenoTK34EMHeBPDCpqNDz8UVNk</X509Certificate></X509Data></KeyInfo>"
            "PHNhbWxwOlJlc3BvbnNlIElEPSJfM2FlYjMwNTQtZTg1Zi00MWZhLWEyMGYtMGYyNzhiMzI3ZjRlIiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAxOC0wNC0xNFQwOTo1ODo1OC40NTdaIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly96YjIuemVyb2J1enoubmV0OjYwNDQzL2F1dGhyZXNwIiBJblJlc3BvbnNlVG89ImlkY2YyMjk5YWM1NTFiNDJmMWFhOWI4ODgwNGVkMzA4YzIiIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxJc3N1ZXIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzY4MmZlYmU4LTAyMWItNGZkZS1hYzA5LWU2MDA4NWYwNTE4MS88L0lzc3Vlcj48c2FtbHA6U3RhdHVzPjxzYW1scDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWxwOlN0YXR1cz48QXNzZXJ0aW9uIElEPSJfYzc5YzNlYzgtMWMyNi00NzUyLTk0NDMtMWY3NmViN2Q1ZGQ2IiBJc3N1ZUluc3RhbnQ9IjIwMTgtMDQtMTRUMDk6NTg6NTguNDQyWiIgVmVyc2lvbj0iMi4wIiB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+PElzc3Vlcj5odHRwczovL3N0cy53aW5kb3dzLm5ldC82ODJmZWJlOC0wMjFiLTRmZGUtYWMwOS1lNjAwODVmMDUxODEvPC9Jc3N1ZXI+PFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PFNpZ25lZEluZm8+PENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPjxSZWZlcmVuY2UgVVJJPSIjX2M3OWMzZWM4LTFjMjYtNDc1Mi05NDQzLTFmNzZlYjdkNWRkNiI+PFRyYW5zZm9ybXM+PFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvVHJhbnNmb3Jtcz48RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhMjU2Ii8+PERpZ2VzdFZhbHVlPmxrV25SSUlBRm1IVmVXSVpWWGJhZGoxTzRhN05nNDRwL2NIQkZNOHFhYk09PC9EaWdlc3RWYWx1ZT48L1JlZmVyZW5jZT48L1NpZ25lZEluZm8+PFNpZ25hdHVyZVZhbHVlPmRhZ2VaWTV3aWdWVUpSeVg0bUZDZ0dMOVBhajRuVXpsTmFoQ2d4SkcybVU2M0RhTHpldm1qeWRITHVMWnhGR3MrNmxDRDhpb0xjNUpMckp3OFBlKzB3d1hZV0huTFAvWU53eVFSNWI2bVpUZWpOOUQvcFpORGNSdVRiQmZNeEdsTjhWVU5oaWg3OHRVL24xQmxiZE5oSGpBTmVTbGdPVUNlWWlIZWVzekRHaERYMi9RZ1p6OEJDL3FHa2ZBNUlIbHlSVHJBZkRoTmhGNFRpQ1F5N1haaVRqMXZ4WlE2ZDBBcTVGaWhFc0JtVW9qYnI1WW5KSjA2WjZ2KzRCS1lVWXNkUkY5RklWdlVtRCszckZORlJBQjdBMnp6c0RxYk82UUdham5YNURKaWtaNmtvTmFreFBsM3Jqd29lRWxwTzBDSG5oWXcyMEN1U09kMnVhK2ppeHRvdz09PC9TaWduYXR1cmVWYWx1ZT48S2V5SW5mbz48WDUwOURhdGE+PFg1MDlDZXJ0aWZpY2F0ZT5NSUlEQlRDQ0FlMmdBd0lCQWdJUWV2NzZCV3FqV1p4Q2htS2tHcW9BZkRBTkJna3Foa2lHOXcwQkFRc0ZBREF0TVNzd0tRWURWUVFERXlKaFkyTnZkVzUwY3k1aFkyTmxjM05qYjI1MGNtOXNMbmRwYm1SdmQzTXVibVYwTUI0WERURTRNREl4T0RBd01EQXdNRm9YRFRJd01ESXhPVEF3TURBd01Gb3dMVEVyTUNrR0ExVUVBeE1pWVdOamIzVnVkSE11WVdOalpYTnpZMjl1ZEhKdmJDNTNhVzVrYjNkekxtNWxkRENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFNZ21HaVJmTGg2RmRpOTlYSTJWQTNYS0hTdFdOUkxFeTVBdy9neEZ4Y2huaDJrUGRrL2JlakZPczJzd2N4N3lVV3F4dWpqQ05Sc0xCY1dmYUtVbFRucmtZN2k5eDlub1psTXJpamdKeS9MaytISDVIWDI0UFFDRGYrdHdqbkhIeFo5RzYvOFZMTTJlNVpCZVptK3Q3TTN2aHV1bUVIRzNVd2xvTEY2Y1VldVBkVytleG5PQjFVMWZIQklGT0c4bnM0U1NJb3E2enc1cmR0MENTSTYrbDdiMURFalZ2UEx0SkYrenlqbEoxUXA3TmdCdkF3ZGlQaVJNVTRsOElSVmJ1U1ZLb0tZSm95SjRMM2VYc2pjem9CU1RKNlZqVjJteWd6OTZEQzcwTVkzYXZjY0Zyazd0Q0VDNlpsTVJCZlkxWFBMeWxkVDd0c1IzRXV6amVjU2ExTThDQXdFQUFhTWhNQjh3SFFZRFZSME9CQllFRklrczFzcml4anBTTFhlaVI4ekVTNWNUWTZmQk1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQ0t0aGZLNEMzMURNdUR5UVpWUzNGNys0RXZsZDNoaml3cXUydUdESytxRlphcy9EL2VEdW54c0ZwaXdxQzAxUklNRkZOOHl2bU1qSHBoTEhpQkhXeGNCVFMrdG03QWhtQXZXTWR4TzVsekpMUytVV0F5UEY1SUNST2U4TXU5aU5KaU81SmxDbzBXcHVpOVJiQjFDODFYaGF4MWdXSEsyNDVFU0w2azdZV3Z5TVlXckdxcjFOdVFjTlMwQi9BSVQxTnNqMVdZN2VmTUpRT21uTUhrUFVUV3J5VlpsdGhpall5ZDdQMkd6NnJZNWE4MURBRnFoRE5KbDJwR0lBRTZIV3RTemVVRWgzakNzSEVrb2dsS2ZtNFZyR0pFdVhjQUxtZkNNYmRmVHZ0dTRybHNhUDJoUWFkK01HL0tKRmxlbm9USzM0RU1IZUJQRENwcU5EejhVVk5rPC9YNTA5Q2VydGlmaWNhdGU+PC9YNTA5RGF0YT48L0tleUluZm8+PC9TaWduYXR1cmU+PFN1YmplY3Q+PE5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnBlcnNpc3RlbnQiPnhKeGRxUzhXMlVYYXdiWlpxcEdGWEtHNHVFbU81R2ppaktEMlJrTWlwQm88L05hbWVJRD48U3ViamVjdENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpjbTpiZWFyZXIiPjxTdWJqZWN0Q29uZmlybWF0aW9uRGF0YSBJblJlc3BvbnNlVG89ImlkY2YyMjk5YWM1NTFiNDJmMWFhOWI4ODgwNGVkMzA4YzIiIE5vdE9uT3JBZnRlcj0iMjAxOC0wNC0xNFQxMDowMzo1OC40NDJaIiBSZWNpcGllbnQ9Imh0dHBzOi8vemIyLnplcm9idXp6Lm5ldDo2MDQ0My9hdXRocmVzcCIvPjwvU3ViamVjdENvbmZpcm1hdGlvbj48L1N1YmplY3Q+PENvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDE4LTA0LTE0VDA5OjUzOjU4LjQ0MloiIE5vdE9uT3JBZnRlcj0iMjAxOC0wNC0xNFQxMDo1Mzo1OC40NDJaIj48QXVkaWVuY2VSZXN0cmljdGlvbj48QXVkaWVuY2U+aHR0cHM6Ly96YjIuemVyb2J1enoubmV0OjYwNDQzL2F1dGhyZXNwPC9BdWRpZW5jZT48L0F1ZGllbmNlUmVzdHJpY3Rpb24+PC9Db25kaXRpb25zPjxBdHRyaWJ1dGVTdGF0ZW1lbnQ+PEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2lkZW50aXR5L2NsYWltcy90ZW5hbnRpZCI+PEF0dHJpYnV0ZVZhbHVlPjY4MmZlYmU4LTAyMWItNGZkZS1hYzA5LWU2MDA4NWYwNTE4MTwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2lkZW50aXR5L2NsYWltcy9vYmplY3RpZGVudGlmaWVyIj48QXR0cmlidXRlVmFsdWU+Y2NmYjM3ODgtODI0MS00YWZlLTg4OTctZjMxM2YzNWY5ZTM3PC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48QXR0cmlidXRlIE5hbWU9Imh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL25hbWUiPjxBdHRyaWJ1dGVWYWx1ZT5maXN4dDFAYXp1cmV3aXJlLm9ubWljcm9zb2Z0LmNvbTwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2lkZW50aXR5L2NsYWltcy9kaXNwbGF5bmFtZSI+PEF0dHJpYnV0ZVZhbHVlPmZpc3h0MTwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2lkZW50aXR5L2NsYWltcy9pZGVudGl0eXByb3ZpZGVyIj48QXR0cmlidXRlVmFsdWU+aHR0cHM6Ly9zdHMud2luZG93cy5uZXQvNjgyZmViZTgtMDIxYi00ZmRlLWFjMDktZTYwMDg1ZjA1MTgxLzwvQXR0cmlidXRlVmFsdWU+PC9BdHRyaWJ1dGU+PEF0dHJpYnV0ZSBOYW1lPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL2NsYWltcy9hdXRobm1ldGhvZHNyZWZlcmVuY2VzIj48QXR0cmlidXRlVmFsdWU+aHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2F1dGhlbnRpY2F0aW9ubWV0aG9kL3Bhc3N3b3JkPC9BdHRyaWJ1dGVWYWx1ZT48L0F0dHJpYnV0ZT48L0F0dHJpYnV0ZVN0YXRlbWVudD48QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDE4LTA0LTE0VDA5OjU4OjU1LjYxM1oiIFNlc3Npb25JbmRleD0iX2M3OWMzZWM4LTFjMjYtNDc1Mi05NDQzLTFmNzZlYjdkNWRkNiI+PEF1dGhuQ29udGV4dD48QXV0aG5Db250ZXh0Q2xhc3NSZWY+dXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFjOmNsYXNzZXM6UGFzc3dvcmQ8L0F1dGhuQ29udGV4dENsYXNzUmVmPjwvQXV0aG5Db250ZXh0PjwvQXV0aG5TdGF0ZW1lbnQ+PC9Bc3NlcnRpb24+PC9zYW1scDpSZXNwb25zZT4K"
            "_c79c3ec8-1c26-4752-9443-1f76eb7d5dd6"
            (Right ())
          ]
