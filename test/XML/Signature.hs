{-# LANGUAGE OverloadedStrings #-}
module XML.Signature (tests) where

import Data.List.NonEmpty (NonEmpty(..))
import qualified Test.HUnit as U
import qualified Text.XML.HXT.DOM.QualifiedName as HXT
import qualified Text.XML.HXT.DOM.XmlNode as HXT

import SAML2.XML
import SAML2.XML.Signature

import XML

tests :: U.Test
tests = U.test
  [ testXML "test/XML/signature-example.xml" $
    Signature (Just "MyFirstSignature")
      (SignedInfo Nothing
        (CanonicalizationMethod
          (Preidentified CanonicalXML10)
          [])
        (SignatureMethod
          (Preidentified SignatureDSA_SHA1)
          Nothing
          [])
        (Reference Nothing
          (Just $ readURI "http://www.w3.org/TR/xml-stylesheet/")
          Nothing
          (Just $ Transforms $
            Transform
              (Preidentified TransformBase64)
              []
            :| [])
          (DigestMethod
            (Preidentified DigestSHA1)
            [])
          "\143\169p\199z\239\DLE\243\180\188\171L\186\158\rm\229n\242y"
        :| Reference Nothing
          (Just $ readURI "http://www.w3.org/TR/REC-xml-names/")
          Nothing
          (Just $ Transforms $
            Transform
              (Preidentified TransformBase64)
              []
            :| [])
          (DigestMethod
            (Preidentified DigestSHA1)
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
            (readURI "#MyFirstSignature")
            (HXT.mkElement (HXT.mkQName "ts" "timestamp" "http://www.example.org/rfc/rfcxxxx.txt")
              []
              [HXT.mkText "\n           this is a test of the mixed content model"]
            :| [])
          :| [])]]

  , testXML "http://www.w3.org/TR/xmldsig-core/signature-example-rsa.xml" $
    Signature Nothing
      (SignedInfo Nothing
        (CanonicalizationMethod 
          (Preidentified CanonicalXML10)
          [])
        (SignatureMethod 
          (Preidentified SignatureRSA_SHA1)
          Nothing
          [])
        (Reference Nothing
          (Just $ readURI "http://www.w3.org/TR/xml-stylesheet")
          Nothing
          Nothing
          (DigestMethod 
            (Preidentified DigestSHA1)
            [])
          "\235Cof\251]L\US\187RyK\167\241\246\226\158\225\225\187"
        :| []))
      (SignatureValue Nothing
        "\142\228\185F\DC2|\243\138\168\NAK\US\US\149U\221\254\182\235H5F\159\141\STXj\152\SOH\238\167\144\137?\171\175C^\144D:\EOTxT\ETX\199S\223\224BL\NAK\DLE#GA\142Y\165\246\\3\DLE\213\239K\205\243D@\163\205v\204E5-U\152\143dm\169\168\163\231/f\DC4\220\SIz\227\149\STX\141\&5\212\250\&8\ENQ\186k\251\147\191!\137\224\ACK\SI3\\\139\227\208\244\164f\155\255\226q>\201i\140\237\130\222")
      (Just $ KeyInfo Nothing $
        KeyInfoKeyValue (RSAKeyValue
          129320787110389946406925163824095500161767249273623083115363317842079233133623467127773858023148958966585889333894288698085674111884585270272937137414571531865090153762072690670922714784242933462808045060688046441910524319219807614054721975863956765214954333806674482022007523948700289932875920496009317903247
          65537)
        :| KeyInfoX509Data 
          (X509SubjectName "\n        CN=Merlin Hughes,O=Baltimore Technologies\\, Ltd.,ST=Dublin,C=IE\n      "
          :| X509IssuerSerial 
            "\n          CN=Test RSA CA,O=Baltimore Technologies\\, Ltd.,ST=Dublin,C=IE\n        "
            970849928
          : X509Certificate
            "0\130\STXx0\130\SOH\225\160\ETX\STX\SOH\STX\STX\EOT9\221\254\136\&0\r\ACK\t*\134H\134\247\r\SOH\SOH\EOT\ENQ\NUL0[1\v0\t\ACK\ETXU\EOT\ACK\DC3\STXIE1\SI0\r\ACK\ETXU\EOT\b\DC3\ACKDublin1%0#\ACK\ETXU\EOT\n\DC3\FSBaltimore Technologies, Ltd.1\DC40\DC2\ACK\ETXU\EOT\ETX\DC3\vTest RSA CA0\RS\ETB\r001006163207Z\ETB\r011006163204Z0]1\v0\t\ACK\ETXU\EOT\ACK\DC3\STXIE1\SI0\r\ACK\ETXU\EOT\b\DC3\ACKDublin1%0#\ACK\ETXU\EOT\n\DC3\FSBaltimore Technologies, Ltd.1\SYN0\DC4\ACK\ETXU\EOT\ETX\DC3\rMerlin Hughes0\129\159\&0\r\ACK\t*\134H\134\247\r\SOH\SOH\SOH\ENQ\NUL\ETX\129\141\NUL0\129\137\STX\129\129\NUL\184(\174\146\152\SOh\233\171\171W\207Q1\247\b\ENQ\241\184Y\143\142\201\146\226\&9\211+\SUB\239\211\rI)\197\237'c7jF\149\213\223\228j\187\201\150g\154\163m#7/k\251\251\202\194&\227\&3\190\197\251v\200\145\227\EOT\SUB`\bRq\\\136\153\DC1\250(N\237\190\FSN\230'\DC2/1\RS\219\184\136\201\250\CAN\224\193\160L\234\NAK\ACK\GSw\202x\190\182A\178\251\&8\226t\235K\202\178\202\SYN\218\235\143\STX\ETX\SOH\NUL\SOH\163G0E0\RS\ACK\ETXU\GS\DC1\EOT\ETB0\NAK\129\DC3merlin@baltimore.ie0\SO\ACK\ETXU\GS\SI\SOH\SOH\255\EOT\EOT\ETX\STX\a\128\&0\DC3\ACK\ETXU\GS#\EOT\f0\n\128\bI\224\173\146\NAK\130\237\&70\r\ACK\t*\134H\134\247\r\SOH\SOH\EOT\ENQ\NUL\ETX\129\129\NULrn\224\149j\253i\215+j*\169\242\214\169\235\&9\188s\173}\DEL\217\132(\197\200\&3!\206\201H\241\169\186\218\ACK^w\ACK} \134H\194SQ2\241\ETX@\GS\179v\207\222\DLE\EM\200\SOH\ETX\229\255$K\b\179\159fv\192\240\245\235lS\249\138\v7\169\ENQ\146p\NAK#eX\226\147\190<\GSM\172QVNk\221\FS\210be\218\242l\253\FS2-n\255\184 \US\v\242?\147\220F\175\183\231z\130\SYN"
          : [])
        : [])
      []

  , testXML "http://www.w3.org/TR/xmldsig-core/signature-example-dsa.xml" $
    Signature Nothing
      (SignedInfo Nothing
        (CanonicalizationMethod 
          (Preidentified CanonicalXML10)
          [])
        (SignatureMethod
          (Preidentified SignatureDSA_SHA1)
          Nothing
          [])
        (Reference Nothing
          (Just $ readURI "http://www.w3.org/TR/xml-stylesheet")
          Nothing
          Nothing
          (DigestMethod
            (Preidentified DigestSHA1)
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
        :| KeyInfoX509Data
          (X509SubjectName "\n        CN=Merlin Hughes,O=Baltimore Technologies\\, Ltd.,ST=Dublin,C=IE\n      "
          :| X509IssuerSerial 
            "\n          CN=Test DSA CA,O=Baltimore Technologies\\, Ltd.,ST=Dublin,C=IE\n        "
            970849936
          : X509Certificate "0\130\ETX70\130\STX\245\160\ETX\STX\SOH\STX\STX\EOT9\221\254\144\&0\t\ACK\a*\134H\206\&8\EOT\ETX0[1\v0\t\ACK\ETXU\EOT\ACK\DC3\STXIE1\SI0\r\ACK\ETXU\EOT\b\DC3\ACKDublin1%0#\ACK\ETXU\EOT\n\DC3\FSBaltimore Technologies, Ltd.1\DC40\DC2\ACK\ETXU\EOT\ETX\DC3\vTest DSA CA0\RS\ETB\r001006163215Z\ETB\r011006163214Z0]1\v0\t\ACK\ETXU\EOT\ACK\DC3\STXIE1\SI0\r\ACK\ETXU\EOT\b\DC3\ACKDublin1%0#\ACK\ETXU\EOT\n\DC3\FSBaltimore Technologies, Ltd.1\SYN0\DC4\ACK\ETXU\EOT\ETX\DC3\rMerlin Hughes0\130\SOH\182\&0\130\SOH+\ACK\a*\134H\206\&8\EOT\SOH0\130\SOH\RS\STX\129\129\NUL\218&7\195N\182\176\&0w\252\&2%-c\158\ESC\223\184R\153\131gGr\169\EM=t\185MC\170\154\\\142\237:\184\221\"\EM\186\159\247\142\195\142@B\219\152J\158\172\164+}q\a\r\EOT\b\246\216\171\242\130\247\201 \133\215\246\196\144\174\232\US\SUB\168\159y+\216\221U\249I\221c\251=\fI\159\231\230\&3m\243\203\161\216-uH\n\151\234z\215M\143\245G\t(Y\DC3v\221&!:V\134\210\NAK\STX\NAK\NUL\244\RSr\164\182=\164\195\166\183\DLE\158L1\224\193\211Exk\STX\129\128\&2\225\128\150\167\129\213\172~\191#\182\248\235.n8e\238\145\241.\238;D\129\254\252\206v\SO1\DC2\ETX\210\140J\188\&3\177\140|\200\212vZ\138\SOH\202\177\&4\183\167\238\209Y\220+\181\n\242\137N\226\222\240\166\253\179\224\SOHP=\NAKB(\\(\210\168'\229\162\136\144\128\134\&2Z\209\203\205Z\189\189\187\192g\SYN\162\216q\222#\207\&2\209W\182\128\234+BH\181\162=G\204\220\214k\ENQ\132\205F(\198\ETX\129\132\NUL\STX\129\128r\208<`lk\182x \255\&2\149\190\161\SOy\249\240\153X\133\206\215'<\SYN\SI\148\155/\135\172\138#\136\131\155\175\US\158\158\f\139tk'\166\217\ETX(\ENQ\173B\DLE/\DC2\227W\227\137\182\STX@\DC2\218\&4\196\v>1\232n\171P\228HQ)?z\ETX\204$\206\178\179\162KP\240A\238(!\190\243VO\253\151\182\143\180\147\a[B\213\148\199pd\209M4\154*1\196\246e\240\143\173\251\216\189\r\163G0E0\RS\ACK\ETXU\GS\DC1\EOT\ETB0\NAK\129\DC3merlin@baltimore.ie0\SO\ACK\ETXU\GS\SI\SOH\SOH\255\EOT\EOT\ETX\STX\a\128\&0\DC3\ACK\ETXU\GS#\EOT\f0\n\128\bBY@m\n\193\SYN\207\&0\t\ACK\a*\134H\206\&8\EOT\ETX\ETX1\NUL0.\STX\NAK\NUL\174,\145a\ENQb\n\224\129\162@\242\246\NUL\193(\224\215o\138\STX\NAK\NUL\192t\232\239\ax\180Cp\244\176\n>IP\255\190\US\US_"
          : [])
        : [])
      []
  ]
