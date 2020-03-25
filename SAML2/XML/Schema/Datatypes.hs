{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE ViewPatterns #-}
-- |
-- XML Schema Datatypes
--
-- <http://www.w3.org/TR/2004/REC-xmlschema-2-20041028/> (selected portions)
module SAML2.XML.Schema.Datatypes where

import Prelude hiding (String)

import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Base64 as B64
import Data.Char (isDigit)
import Data.Char.Properties.XMLCharProps (isXmlSpaceChar, isXmlNameChar)
import Data.Fixed (Pico, showFixed)
import Data.List (elemIndex)
import qualified Data.Time.Clock as Time
import Data.Time.Format (formatTime, parseTimeM, defaultTimeLocale)
import Data.Word (Word16)
import qualified Network.URI as URI
import qualified Text.XML.HXT.Arrow.Pickle.Schema as XPS
import Text.XML.HXT.DOM.QualifiedName (isNCName)
import qualified Text.XML.HXT.DOM.XmlNode as XN
import qualified Text.XML.HXT.XMLSchema.DataTypeLibW3CNames as XSD

import qualified Text.XML.HXT.Arrow.Pickle.Xml.Invertible as XP

-- |§3.2.1
type String = [Char]

xpString :: XP.PU String
xpString = XP.xpTextDT (XPS.scDTxsd XSD.xsd_string [])

-- |§3.2.1
type Boolean = Bool

xpBoolean :: XP.PU Boolean
xpBoolean = XP.xpWrapEither
  ( \s -> case s of
      "true" -> Right True
      "false" -> Right False
      "1" -> Right True
      "0" -> Right False
      _ -> Left "invalid boolean"
  , \b -> if b then "true" else "false"
  ) $ XP.xpTextDT $ XPS.scDTxsd XSD.xsd_boolean []

-- |§3.2.6 specifies a complete ISO8601 6-component duration; for SAML2 purposes we don't overly care
type Duration = Time.NominalDiffTime

xpDuration :: XP.PU Duration
xpDuration = XP.xpWrapEither
  ( maybe (Left "invalid duration") (Right . realToFrac) . prd
  , \t -> (if signum t < 0 then ('-':) else id)
    $ 'P':'T': showFixed True (abs $ realToFrac t :: Pico) ++ "S"
  ) $ XP.xpTextDT $ XPS.scDTxsd XSD.xsd_duration [] where
  prd ('-':s) = negate <$> prp s
  prd ('+':s) = prp s
  prd s = prp s
  prp ('P':s) = pru (0 :: Pico) prt [('Y',31556952),('M',2629746),('D',86400)] s
  prp _ = Nothing
  prt x "" = Just x
  prt x ('T':s) = pru x prs [('H',3600),('M',60)] s
  prt _ _ = Nothing
  prs x "" = Just x
  prs x s = case span isDigit s of
    (d@(_:_),'.':(span isDigit -> (p,"S"))) -> Just $ x + read (d ++ '.' : p)
    (d@(_:_),"S") -> Just $ x + read d
    _ -> Nothing
  pru x c ul s = case span isDigit s of
    (d@(_:_),uc:sr) | (_,uv):ur <- dropWhile ((uc /=) . fst) ul -> pru (x + uv * read d) c ur sr
    _ -> c x s

-- |§3.2.7 theoretically allows timezones, but SAML2 does not use them
type DateTime = Time.UTCTime

xpDateTime :: XP.PU DateTime
xpDateTime = XP.PU
  { XP.theSchema = XPS.scDTxsd XSD.xsd_dateTime []
  , XP.appPickle = XP.putCont . XN.mkText . tweakTimeString . formatTime defaultTimeLocale fmtz
  , XP.appUnPickle = XP.getCont >>= XP.liftMaybe "dateTime expects text" . XN.getText >>= parseTime
  }
  where
  -- timezone must be 'Z', and MicrosoftS(tm) Azure(tm) will choke when it is ommitted.  (error
  -- messages are utterly unhelpful.)
  fmtz = "%Y-%m-%dT%H:%M:%S%QZ"

  parseTime dateString = maybe (XP.throwMsg $ "can't parse date " <> dateString) pure
    $ parseTimeM True defaultTimeLocale fmtz dateString

  -- adding '%Q' may be longer than 7 digits, which makes MicrosoftS(tm) Azure(tm) choke.
  tweakTimeString :: String -> String
  tweakTimeString s = case elemIndex '.' s of
    Nothing -> s
    Just i -> case splitAt i s of
      (t, u) -> case splitAt 8 u of
        (_, "") -> t ++ u
        (v, _)  -> t ++ v ++ "Z"

-- |§3.2.16
type Base64Binary = BS.ByteString

xpBase64Binary :: XP.PU Base64Binary
xpBase64Binary = XP.xpWrapEither
  ( B64.decode . BS.pack . filter (not . isXmlSpaceChar)
  , BS.unpack . B64.encode
  ) $ XP.xpText0DT $ XPS.scDTxsd XSD.xsd_base64Binary []

-- |§3.2.17
type AnyURI = URI.URI

xpAnyURI :: XP.PU AnyURI
xpAnyURI = XP.xpWrapEither
  ( maybe (Left "invalid anyURI") Right . URI.parseURIReference
  , \u -> URI.uriToString id u "")
  $ XP.xpText0DT $ XPS.scDTxsd XSD.xsd_anyURI []

-- |§3.3.1
type NormalizedString = String
-- |§3.3.2
type Token = NormalizedString
-- |§3.3.3
type Language = Token

xpLanguage :: XP.PU Language
xpLanguage = XP.xpTextDT $ XPS.scDTxsd XSD.xsd_language []

-- |§3.3.4
type NMTOKEN = Token

isNMTOKEN :: Token -> Bool
isNMTOKEN [] = False
isNMTOKEN s = all isXmlNameChar s

xpNMTOKEN :: XP.PU NMTOKEN
xpNMTOKEN = XP.xpWrapEither
  ( \x -> if isNMTOKEN x then Right x else Left "NMTOKEN expected"
  , id
  ) $ XP.xpTextDT $ XPS.scDTxsd XSD.xsd_NMTOKEN []

-- |§3.3.5
type NMTOKENS = [NMTOKEN]

xpNMTOKENS :: XP.PU NMTOKENS
xpNMTOKENS = XP.xpWrapEither
  ( \x -> case words x of
      [] -> Left "NMTOKENS expected"
      l | all isNMTOKEN l -> Right l
      _ -> Left "NMTOKENS expected"
  , unwords
  ) $ XP.xpTextDT $ XPS.scDTxsd XSD.xsd_NMTOKENS []

-- |§3.3.8
type ID = String
type NCName = String

xpNCName :: XP.PU NCName
xpNCName = XP.xpWrapEither
  ( \x -> if isNCName x then Right x else Left "NCName expected"
  , id
  ) $ XP.xpTextDT $ XPS.scDTxsd XSD.xsd_NCName []

xpID :: XP.PU ID
xpID = xpNCName{ XP.theSchema = XPS.scDTxsd XSD.xsd_ID [] }

-- |§3.3.13
xpInteger :: XP.PU Integer
xpInteger = XP.xpPrim{ XP.theSchema = XPS.scDTxsd XSD.xsd_integer [] }

-- |§3.3.20
type NonNegativeInteger = Word

xpNonNegativeInteger :: XP.PU NonNegativeInteger
xpNonNegativeInteger = XP.xpPrim{ XP.theSchema = XPS.scDTxsd XSD.xsd_nonNegativeInteger [] }

-- |§3.3.23
type UnsignedShort = Word16

xpUnsignedShort :: XP.PU UnsignedShort
xpUnsignedShort = XP.xpPrim{ XP.theSchema = XPS.scDTxsd XSD.xsd_unsignedShort [] }

-- |§3.3.20
type PositiveInteger = NonNegativeInteger

xpPositiveInteger :: XP.PU PositiveInteger
xpPositiveInteger = XP.xpWrapEither
  ( \x -> if x > 0 then Right x else Left "0 is not positive"
  , id
  ) $ XP.xpPrim{ XP.theSchema = XPS.scDTxsd XSD.xsd_positiveInteger [] }
