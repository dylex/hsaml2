-- |
-- XML Signature Syntax and Processing
--
-- <http://www.w3.org/TR/2008/REC-xmldsig-core-20080610/> (selected portions)
module SAML2.XML.Signature
  ( module SAML2.XML.Signature.Schema
  , SigningKey(..)
  , PublicKeys(..)
  , signingKeySignatureAlgorithm
  , signBase64
  , verifyBase64
  ) where

import Control.Applicative ((<|>))
import Control.Monad ((<=<))
import Crypto.Number.Serialize (i2ospOf_, os2ip)
import Crypto.Hash.Algorithms (SHA1(SHA1))
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.RSA.Types as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Lazy as BSL
import qualified Data.List.NonEmpty as NonEmpty
import Data.Maybe (listToMaybe)
import Data.Monoid ((<>))
import qualified Text.XML.HXT.Core as HXT
import qualified Text.XML.HXT.Arrow.XmlState.RunIOStateArrow as RunHXT
import qualified Text.XML.HXT.DOM.ShowXml as DOM

import SAML2.XML
import SAML2.XML.Canonical
import SAML2.XML.Signature.Schema

applyTransformsBytes :: [Transform] -> BSL.ByteString -> IO BSL.ByteString
applyTransformsBytes [] = return
applyTransformsBytes (t : _) = fail ("applyTransformsBytes: unsupported Signature " ++ show t)

applyTransformsXML :: [Transform] -> HXT.XmlTree -> IO BSL.ByteString
applyTransformsXML (Transform (Identified (TransformCanonicalization c)) [] : tl) =
  applyTransformsBytes tl . BSL.fromStrict
  <=< maybe (fail "applyTransformXML: canonicalization failed") return . listToMaybe . snd
  <=< HXT.runIOSLA (canonicalize c) (RunHXT.initialState ())
applyTransformsXML (Transform (Identified TransformEnvelopedSignature) [] : tl) =
  -- XXX assumes "this" signature in top-level
  applyTransformsXML tl
  . head . HXT.runLA (HXT.processChildren 
    $ HXT.none `HXT.when` (HXT.isElem HXT.>>> HXT.hasQName (mkNName ns "Signature")))
applyTransformsXML tl = applyTransformsBytes tl . DOM.xshowBlob . return

applyTransforms :: Maybe Transforms -> HXT.XmlTree -> IO BSL.ByteString
applyTransforms = applyTransformsXML . maybe [] (NonEmpty.toList . transforms)

data SigningKey
  = SigningKeyDSA DSA.KeyPair
  | SigningKeyRSA RSA.KeyPair
  deriving (Eq, Show)

data PublicKeys = PublicKeys
  { publicKeyDSA :: Maybe DSA.PublicKey
  , publicKeyRSA :: Maybe RSA.PublicKey
  } deriving (Eq, Show)

instance Monoid PublicKeys where
  mempty = PublicKeys Nothing Nothing
  PublicKeys dsa1 rsa1 `mappend` PublicKeys dsa2 rsa2 =
    PublicKeys (dsa1 <|> dsa2) (rsa1 <|> rsa2)

signingKeySignatureAlgorithm :: SigningKey -> SignatureAlgorithm
signingKeySignatureAlgorithm (SigningKeyDSA _) = SignatureDSA_SHA1
signingKeySignatureAlgorithm (SigningKeyRSA _) = SignatureRSA_SHA1

signBase64 :: SigningKey -> BS.ByteString -> IO BS.ByteString
signBase64 sk = fmap Base64.encode . signBytes sk where
  signBytes (SigningKeyDSA k) b = do
    s <- DSA.sign (DSA.toPrivateKey k) SHA1 b
    return $ i2ospOf_ 20 (DSA.sign_r s) <> i2ospOf_ 20 (DSA.sign_s s)
  signBytes (SigningKeyRSA k) b =
    either (fail . show) return =<< RSA.signSafer (Just SHA1) (RSA.toPrivateKey k) b

verifyBase64 :: PublicKeys -> IdentifiedURI SignatureAlgorithm -> BS.ByteString -> BS.ByteString -> Maybe Bool
verifyBase64 pk alg m = either (const $ Just False) (verifyBytes pk alg) . Base64.decode where
  verifyBytes PublicKeys{ publicKeyDSA = Just k } (Identified SignatureDSA_SHA1) sig = Just $
    BS.length sig == 40 &&
    DSA.verify SHA1 k DSA.Signature{ DSA.sign_r = os2ip r, DSA.sign_s = os2ip s } m
    where (r, s) = BS.splitAt 20 sig
  verifyBytes PublicKeys{ publicKeyRSA = Just k } (Identified SignatureRSA_SHA1) sig = Just $
    RSA.verify (Just SHA1) k m sig
  verifyBytes _ _ _ = Nothing
