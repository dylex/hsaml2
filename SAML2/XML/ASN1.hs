module SAML2.XML.ASN1 where

import Control.Arrow (left)
import Data.ASN1.Types (ASN1, ASN1Object(..))
import Data.ASN1.BinaryEncoding (BER(BER), DER(DER))
import Data.ASN1.Encoding (decodeASN1', encodeASN1')
import qualified Data.X509 as X509

import qualified Text.XML.HXT.Arrow.Pickle.Xml.Invertible as XP
import qualified SAML2.XML.Schema as XS

xpASN1 :: XP.PU [ASN1]
xpASN1 = XP.xpWrapEither
  ( left show . decodeASN1' BER
  , encodeASN1' DER
  ) XS.xpBase64Binary

xpASN1Object :: ASN1Object a => XP.PU a
xpASN1Object = XP.xpWrapEither
  ( either Left check . fromASN1
  , (`toASN1` [])
  ) xpASN1 where
  check (x, []) = Right x
  check _ = Left "trailing ASN1 data"

xpX509Signed :: (Show a, Eq a, ASN1Object a) => XP.PU (X509.SignedExact a)
xpX509Signed = XP.xpWrapEither
  ( X509.decodeSignedObject
  , X509.encodeSignedObject
  ) XS.xpBase64Binary
