{-# LANGUAGE BangPatterns        #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE RankNTypes          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE ViewPatterns        #-}
-- |
-- XML Signature Syntax and Processing
--
-- <http://www.w3.org/TR/2008/REC-xmldsig-core-20080610/> (selected portions)
module SAML2.XML.Signature
  ( module SAML2.XML.Signature.Types
  , generateReference
  , SigningKey(..)
  , PublicKeys(..)
  , signingKeySignatureAlgorithm
  , signBase64
  , verifyBase64
  , generateSignature
  , verifySignature, SignatureError(..)
  , applyCanonicalization
  , applyTransforms
  ) where

import GHC.Stack
import System.IO.Silently (hCapture)
import System.IO (stdout, stderr)
import Control.Applicative ((<|>))
import Control.Exception (SomeException, try, throwIO, ErrorCall(ErrorCall))
import Control.Monad ((<=<))
import Control.Monad.Except
import Crypto.Number.Basic (numBytes)
import Crypto.Number.Serialize (i2ospOf_, os2ip)
import Crypto.Hash (hashlazy, SHA1(..), SHA256(..), SHA512(..), RIPEMD160(..))
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.RSA.Types as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Lazy as BSL
import qualified Data.List.NonEmpty as NonEmpty
import Data.Either (isRight, lefts)
import Data.List (intercalate)
import Data.Semigroup (Semigroup(..))
import Data.String.Conversions hiding ((<>))
import Data.Monoid (Monoid(..))
import qualified Data.X509 as X509
import Network.URI (URI(..))
import qualified Text.XML.HXT.Core as HXT
import qualified Text.XML.HXT.DOM.ShowXml as DOM
import qualified Text.XML.HXT.DOM.XmlNode as DOM

import SAML2.XML
import SAML2.XML.Canonical
import qualified Text.XML.HXT.Arrow.Pickle.Xml.Invertible as XP
import SAML2.XML.Signature.Types
import SAML2.XML.Schema.Datatypes (Base64Binary)

isDSElem :: HXT.ArrowXml a => String -> a HXT.XmlTree HXT.XmlTree
isDSElem n = HXT.isElem HXT.>>> HXT.hasQName (mkNName ns n)

getID :: HXT.ArrowXml a => String -> a HXT.XmlTree HXT.XmlTree
getID = HXT.deep . HXT.hasAttrValue "ID" . (==)

applyCanonicalization :: CanonicalizationMethod -> Maybe String -> HXT.XmlTree -> IO BS.ByteString
applyCanonicalization (CanonicalizationMethod (Identified a) ins []) = canonicalize a ins
applyCanonicalization m = fail $ "applyCanonicalization: unsupported " ++ show m

applyTransformsBytes :: [Transform] -> BSL.ByteString -> IO BSL.ByteString
applyTransformsBytes [] = return
applyTransformsBytes ts@(_:_) = fail ("applyTransforms: unsupported XML:DSig transform: " ++ show ts)

applyTransformsXML :: [Transform] -> HXT.XmlTree -> IO BSL.ByteString
applyTransformsXML (Transform (Identified (TransformCanonicalization a)) ins x : tl) =
  applyTransformsBytes tl . BSL.fromStrict
  <=< applyCanonicalization (CanonicalizationMethod (Identified a) ins (map (XP.pickleDoc XP.xpickle) x)) Nothing
applyTransformsXML (Transform (Identified TransformEnvelopedSignature) Nothing [] : tl) =
  -- XXX assumes "this" signature in top-level
  applyTransformsXML tl
  . head . HXT.runLA (HXT.processChildren $ HXT.processChildren
    $ HXT.neg (isDSElem "Signature"))
applyTransformsXML tl = applyTransformsBytes tl . DOM.xshowBlob . return

applyTransforms :: Maybe Transforms -> HXT.XmlTree -> IO BSL.ByteString
applyTransforms = applyTransformsXML . maybe [] (NonEmpty.toList . transforms)

applyDigest :: DigestMethod -> BSL.ByteString -> BS.ByteString
applyDigest (DigestMethod (Identified DigestSHA1) []) = BA.convert . hashlazy @SHA1
applyDigest (DigestMethod (Identified DigestSHA256) []) = BA.convert . hashlazy @SHA256
applyDigest (DigestMethod (Identified DigestSHA512) []) = BA.convert . hashlazy @SHA512
applyDigest (DigestMethod (Identified DigestRIPEMD160) []) = BA.convert . hashlazy @RIPEMD160
applyDigest d = error $ "unsupported " ++ show d

generateReference :: Reference -> HXT.XmlTree -> IO Reference
generateReference r x = do
  t <- applyTransforms (referenceTransforms r) x
  let d = applyDigest (referenceDigestMethod r) t
  return r
    { referenceDigestValue = d }

-- | Re-compute the digest (after transforms) of a 'Reference'd subtree of an xml document and
-- compare it against the one given in the 'Reference'.  If it matches, return the xml ID;
-- otherwise, return an error string.
verifyReference :: HasCallStack => Reference -> HXT.XmlTree -> IO (Either String String)
verifyReference r doc = case referenceURI r of
  Just URI{ uriScheme = "", uriAuthority = Nothing, uriPath = "", uriQuery = "", uriFragment = '#':xid } ->
    case HXT.runLA (getID xid) doc of
      x@[_] -> do
        t :: LBS <- applyTransforms (referenceTransforms r) $ DOM.mkRoot [] x
        let have = applyDigest (referenceDigestMethod r) t
            want = referenceDigestValue r
        return $ if have == want
          then Right xid
          else Left $ "#" <> xid <> ": digest mismatch"
      bad -> return . Left $ "#" <> xid <> ": has " <> show (length bad) <> " matches, should have 1."
  bad -> return . Left $ "unexpected referenceURI: " <> show bad

data SigningKey
  = SigningKeyDSA DSA.KeyPair
  | SigningKeyRSA RSA.KeyPair
  deriving (Eq, Show)

data PublicKeys = PublicKeys
  { publicKeyDSA :: Maybe DSA.PublicKey
  , publicKeyRSA :: Maybe RSA.PublicKey
  } deriving (Eq, Show)

instance Semigroup PublicKeys where
  PublicKeys dsa1 rsa1 <> PublicKeys dsa2 rsa2 =
    PublicKeys (dsa1 <|> dsa2) (rsa1 <|> rsa2)

instance Monoid PublicKeys where
  mempty = PublicKeys Nothing Nothing
  mappend = (<>)

signingKeySignatureAlgorithm :: SigningKey -> SignatureAlgorithm
signingKeySignatureAlgorithm (SigningKeyDSA _) = SignatureDSA_SHA1
signingKeySignatureAlgorithm (SigningKeyRSA _) = SignatureRSA_SHA1

signingKeyValue :: SigningKey -> KeyValue
signingKeyValue (SigningKeyDSA (DSA.toPublicKey -> DSA.PublicKey p y)) = DSAKeyValue
  { dsaKeyValuePQ = Just (DSA.params_p p, DSA.params_q p)
  , dsaKeyValueG = Just (DSA.params_g p)
  , dsaKeyValueY = y
  , dsaKeyValueJ = Nothing
  , dsaKeyValueSeedPgenCounter = Nothing
  }
signingKeyValue (SigningKeyRSA (RSA.toPublicKey -> RSA.PublicKey _ n e)) = RSAKeyValue
  { rsaKeyValueModulus = n
  , rsaKeyValueExponent = e
  }

publicKeyValues :: KeyValue -> PublicKeys
publicKeyValues DSAKeyValue{ dsaKeyValuePQ = Just (p, q), dsaKeyValueG = Just g, dsaKeyValueY = y } = mempty
  { publicKeyDSA = Just $ DSA.PublicKey
    { DSA.public_params = DSA.Params
      { DSA.params_p = p
      , DSA.params_q = q
      , DSA.params_g = g
      }
    , DSA.public_y = y
    }
  }
publicKeyValues RSAKeyValue{ rsaKeyValueModulus = n, rsaKeyValueExponent = e } = mempty
  { publicKeyRSA = Just $ RSA.PublicKey (numBytes n) n e
  }
publicKeyValues _ = mempty

signBytes :: SigningKey -> BS.ByteString -> IO BS.ByteString
signBytes (SigningKeyDSA k) b = do
  s <- DSA.sign (DSA.toPrivateKey k) SHA1 b
  return $ i2ospOf_ 20 (DSA.sign_r s) <> i2ospOf_ 20 (DSA.sign_s s)
signBytes (SigningKeyRSA k) b =
  either (fail . show) return =<< RSA.signSafer (Just SHA1) (RSA.toPrivateKey k) b

-- | indicate verification result; return 'Nothing' if no matching key/alg pair is found
verifyBytes :: PublicKeys -> IdentifiedURI SignatureAlgorithm -> BS.ByteString -> BS.ByteString -> Maybe Bool
verifyBytes PublicKeys{ publicKeyDSA = Just k } (Identified SignatureDSA_SHA1) sig m = Just $
  BS.length sig == 40 &&
  DSA.verify SHA1 k DSA.Signature{ DSA.sign_r = os2ip r, DSA.sign_s = os2ip s } m
  where (r, s) = BS.splitAt 20 sig
verifyBytes PublicKeys{ publicKeyRSA = Just k } (Identified SignatureRSA_SHA1) sig m = Just $
  RSA.verify (Just SHA1) k m sig
verifyBytes PublicKeys{ publicKeyRSA = Just k } (Identified SignatureRSA_SHA256) sig m = Just $
  RSA.verify (Just SHA256) k m sig
verifyBytes _ _ _ _ = Nothing

signBase64 :: SigningKey -> BS.ByteString -> IO BS.ByteString
signBase64 sk = fmap Base64.encode . signBytes sk

verifyBase64 :: PublicKeys -> IdentifiedURI SignatureAlgorithm -> BS.ByteString -> BS.ByteString -> Maybe Bool
verifyBase64 pk alg m = either (const $ Just False) (verifyBytes pk alg m) . Base64.decode where

generateSignature :: SigningKey -> SignedInfo -> IO Signature
generateSignature sk si = do
  -- XXX: samlToDoc may not match later
  six <- applyCanonicalization (signedInfoCanonicalizationMethod si) Nothing $ samlToDoc si
  sv <- signBytes sk six
  return Signature
    { signatureId = Nothing
    , signatureSignedInfo = si
    , signatureSignatureValue = SignatureValue Nothing sv
    , signatureKeyInfo = Just $ KeyInfo Nothing $ KeyInfoKeyValue (signingKeyValue sk) NonEmpty.:| []
    , signatureObject = []
    }

-- deprecated!  use 'verifySignature' instead.  this is left here so it can be used for testing only.
--
-- Exception in IO:  something is syntactically wrong with the input
-- Nothing:          no matching key/alg pairs found
-- Just False:       signature verification failed || bad refs || explicit ref is not among the signed ones
-- Just True:        everything is ok!
_verifySignatureOld :: PublicKeys -> String -> HXT.XmlTree -> IO (Maybe Bool)
_verifySignatureOld pks xid doc = do
  x <- case HXT.runLA (getID xid) doc of
    [x] -> return x
    _ -> fail "verifySignature: element not found"
  sx <- case child "Signature" x of
    [sx] -> return sx
    _ -> fail "verifySignature: Signature not found"
  s@Signature{ signatureSignedInfo = si } <- either fail return $ docToSAML sx
  six <- applyCanonicalization (signedInfoCanonicalizationMethod si) (Just xpath) $ DOM.mkRoot [] [x]
  rl <- mapM (`verifyReference` x) (signedInfoReference si)
  let keys = pks <> foldMap (foldMap keyinfo . keyInfoElements) (signatureKeyInfo s)
      verified :: Maybe Bool
      verified = verifyBytes keys (signatureMethodAlgorithm $ signedInfoSignatureMethod si) (signatureValue $ signatureSignatureValue s) six
      valid :: Bool
      valid = elem (Right xid) rl && all isRight rl
  return $ (valid &&) <$> verified
  where
  child n = HXT.runLA $ HXT.getChildren HXT.>>> isDSElem n HXT.>>> HXT.cleanupNamespaces HXT.collectPrefixUriPairs
  keyinfo (KeyInfoKeyValue kv) = publicKeyValues kv
  keyinfo (X509Data l) = foldMap keyx509d l
  keyinfo _ = mempty
  keyx509d (X509Certificate sc) = keyx509p $ X509.certPubKey $ X509.getCertificate sc
  keyx509d _ = mempty
  keyx509p (X509.PubKeyRSA r) = mempty{ publicKeyRSA = Just r }
  keyx509p (X509.PubKeyDSA d) = mempty{ publicKeyDSA = Just d }
  keyx509p _ = mempty
  xpathsel t = "/*[local-name()='" ++ t ++ "' and namespace-uri()='" ++ namespaceURIString ns ++ "']"
  xpathbase = "/*" ++ xpathsel "Signature" ++ xpathsel "SignedInfo" ++ "//"
  xpath = xpathbase ++ ". | " ++ xpathbase ++ "@* | " ++ xpathbase ++ "namespace::*"


-- | take a public key and an xml node ID that points to the sub-tree that needs to be signed, and
-- return @Right ()@ if it is signed with that key.  otherwise, return a (hopefully helpful) error.
-- use this if you want to verify signatures, and ignore the rest of this module if you can.
--
-- how does this work?:
--   * dig for the subtree of the input with an ID attribute containing xid (the "signed subtree")
--   * parse the 'Signature' subtree in that subtree (we only do envelopped signatures)
--   * get the canonicalized 'SignedInfo' subtree of the signed subtree as bytestring.
--   * call 'verifyReference' on all 'Reference's contained in the parsed signature to make sure input is intact.
--   * call 'verifyBytes' on the canonicalized 'SignedInfo' to make sure the signature is valid.
--
-- the canonicalizations given in the signature are applied to the signed info; the transforms
-- are applied to the signed subtrees.  (this is confusing because one of the transforms is
-- usually a form of canonicalization, but it makes sense if you accept the premise that any
-- of this does.)
verifySignature :: PublicKeys -> String -> HXT.XmlTree -> IO (Either SignatureError ())
verifySignature pks xid doc = runExceptT $ do
  signedSubtree :: HXT.XmlTree
    <- failWith SignatureParseError
      $ getSubtreeWithNamespaces xid doc

  signatureElem@Signature{ signatureSignedInfo = signedInfoTyped } :: Signature
    <- do
        sx :: HXT.XmlTree
          <- let child n = HXT.runLA $ HXT.getChildren HXT.>>> isDSElem n HXT.>>> HXT.cleanupNamespaces HXT.collectPrefixUriPairs
             in case child "Signature" signedSubtree of
            [sx] -> return sx
            _ -> throwError SignatureNotFoundOrEmpty

        case docToSAML sx of
          Left err -> throwError . SignatureParseError $ show err
          Right v -> pure v

  -- validate the hashes
  referenceChecks :: NonEmpty.NonEmpty (Either String String)
    <- failWith (SignatureVerifyReferenceError . (show (signedInfoReference signedInfoTyped) <>))
      . capture' "verifyReference"
      $ mapM (`verifyReference` signedSubtree) (signedInfoReference signedInfoTyped)

  -- all signed subtrees have valid hashes
  unless (all isRight referenceChecks) $
    throwError . SignatureVerifyBadReferences $ (show . lefts . NonEmpty.toList $ referenceChecks)
  -- the subtree we are interested in is among the signed subtrees
  unless (elem (Right xid) referenceChecks) $
    throwError . SignatureVerifyInputNotReferenced $ show referenceChecks

  signedInfoElem :: BS.ByteString
    <- let xpath = mkXPath xpathbase
             where
               xpathsel t = "/*[local-name()='" ++ t ++ "' and namespace-uri()='" ++ namespaceURIString ns ++ "']"
               xpathbase = "/*" ++ xpathsel "Signature" ++ xpathsel "SignedInfo"
       in failWith SignatureCanonicalizationError
          . capture' "applyCanonicalization"
          $ (applyCanonicalization (signedInfoCanonicalizationMethod signedInfoTyped) (Just xpath) $ DOM.mkRoot [] [signedSubtree])

  do
    let keys :: PublicKeys
        keys = pks <> foldMap (foldMap keyinfo . keyInfoElements) (signatureKeyInfo signatureElem)
          where
            keyinfo (KeyInfoKeyValue kv) = publicKeyValues kv
            keyinfo (X509Data l) = foldMap keyx509d l
              where
                keyx509d (X509Certificate sc) = keyx509p $ X509.certPubKey $ X509.getCertificate sc
                keyx509d _ = mempty
                keyx509p (X509.PubKeyRSA r) = mempty{ publicKeyRSA = Just r }
                keyx509p (X509.PubKeyDSA d) = mempty{ publicKeyDSA = Just d }
                keyx509p _ = mempty
            keyinfo _ = mempty

        alg :: IdentifiedURI SignatureAlgorithm
        alg = signatureMethodAlgorithm $ signedInfoSignatureMethod signedInfoTyped

        dig :: Base64Binary
        dig = signatureValue $ signatureSignatureValue signatureElem

    -- validate the signature
    case verifyBytes keys alg dig signedInfoElem of
      Nothing    -> throwError . SignatureVerificationCryptoUnsupported $ show (keys, alg, dig, signedInfoElem)
      Just False -> throwError . SignatureVerificationCryptoFailed      $ show (keys, alg, dig, signedInfoElem)
      Just True  -> pure ()


-- | if name spaces that are declared in doc and used in the signed subtree, we need to copy
-- the declarations into the part the subtree to make it self-contained.  the easiest way to
-- implement that is to use a xml:dsig canonicalization function and do another round of
-- rendering and parsing.
--
-- TODO: there may be a cleaner way to do this.  i know that xml-conduit isn't very interested
-- in getting name spaces right, and HXT doesn't seem to be very successful at it either, but
-- it may just be that i'm unaware of the regions of the HXT jungle that do this.
getSubtreeWithNamespaces :: HasCallStack => String -> HXT.XmlTree -> IO HXT.XmlTree
getSubtreeWithNamespaces xid doc = do
  let xpath = mkXPath $ "//*[@ID=" <> show xid <> "]"
  can :: SBS
    <- liftIO . capture' "fixNamespaces" $
       canonicalize (CanonicalXMLExcl10 True) Nothing (Just xpath) $ DOM.mkRoot [] [doc]
  maybe (throwIO . ErrorCall $ "parse error on canonicalized xml") pure $
    xmlToDoc (cs can)

-- | Capture stdout, stderr to a temp file, and throw an IO error if that file is non-empty.
capture' :: String -> IO a -> IO a
capture' actionName action = hCapture [stdout, stderr] action >>= \case
  ("", !out) -> pure out
  (noise@(_:_), _) -> throwIO . ErrorCall $ actionName <> ": " <> noise

-- | Takes an xpath that works on https://codebeautify.org/Xpath-Tester, but only returns the
-- empty tag stripped of all attributes and children here, and returns an xpath that does what
-- you'd expect.
--
-- Anybody: if you know more about the why, please elaborate.
mkXPath :: String -> String
mkXPath xpathbase = intercalate " | " ((xpathbase <>) <$> ["//.", "//@*", "//namespace::*"])


data SignatureError =
    SignedElementNotFound
  | SignatureNotFoundOrEmpty
  | SignatureParseError String
  | SignatureCanonicalizationError String
  | SignatureVerifyReferenceError String
  | SignatureVerifyBadReferences String
  | SignatureVerifyInputNotReferenced String
  | SignatureVerificationCryptoUnsupported String
  | SignatureVerificationCryptoFailed String
  deriving (Eq, Show)

failWith :: forall m a. (MonadIO m, MonadError SignatureError m)
         => (String -> SignatureError) -> IO a -> m a
failWith mkerr action = either (throwError . mkerr . show) pure =<< liftIO (try @SomeException action)
