{-# LANGUAGE TypeSynonymInstances #-}
-- |
-- XML Schema Datatypes
--
-- <http://www.w3.org/TR/2004/REC-xmlschema-2-20041028/> (selected portions)
module SAML2.XML.Schema.Datatypes where

import Prelude hiding (String)

import Control.Monad (liftM2)
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Base64 as B64
import Data.Char (isDigit)
import Data.Char.Properties.XMLCharProps (isXmlSpaceChar, isXmlNameChar)
import Data.Fixed (Pico, showFixed)
import qualified Data.Time.Clock as Time
import Data.Time.Format (formatTime, parseTimeM, defaultTimeLocale)
import Data.Word (Word16)
import qualified Network.URI as URI
import qualified Text.ParserCombinators.ReadP as RP
import qualified Text.XML.HXT.Arrow.Pickle.Schema as XPS
import Text.XML.HXT.DOM.QualifiedName (isNCName)
import qualified Text.XML.HXT.DOM.XmlNode as XN
import qualified Text.XML.HXT.XMLSchema.DataTypeLibW3CNames as XSD

import qualified SAML2.XML.Pickle as XP

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
  ( prs
  , \t -> (if signum t < 0 then ('-':) else id)
    $ 'P':'T': showFixed True (abs $ realToFrac t :: Pico) ++ "S"
  ) $ XP.xpTextDT $ XPS.scDTxsd XSD.xsd_duration [] where
  prs s = case RP.readP_to_S rpp s of
    [(t,"")] -> Right $ realToFrac (t :: Pico)
    _:_:_ -> Left "ambiguous duration"
    _ -> Left "invalid duration"
  rpp = do
    s <- RP.option '+' $ RP.satisfy (`elem` "+-")
    _ <- RP.char 'P'
    r <- rsum
      [ rpu 31556952 'Y'
      , rpu 2629746 'M'
      , rpu 86400 'D'
      , rp0 $ do
        _ <- RP.char 'T'
        rsum
          [ rpu 3600 'H'
          , rpu 60 'M'
          , rp0 $ do
            sv <- RP.munch1 isDigit
            ss <- RP.option "" $ liftM2 (:) (RP.char '.') (RP.munch isDigit)
            _ <- RP.char 'S'
            return $ read (sv++ss)
          ]
      ]
    return $ if s == '-' then negate r else r
  rpu m u = rp0 $ do
    v <- RP.munch1 isDigit
    _ <- RP.char u
    return $ m * read v
  rp0 = RP.option 0
  rsum [] = return 0
  rsum (x:l) = liftM2 (+) x $ rsum l

-- |§3.2.7 theoretically allows timezones, but SAML2 does not use them
type DateTime = Time.UTCTime

xpDateTime :: XP.PU DateTime
xpDateTime = XP.PU
  { XP.theSchema = XPS.scDTxsd XSD.xsd_dateTime []
  , XP.appPickle = XP.putCont . XN.mkText . formatTime defaultTimeLocale fmt
  , XP.appUnPickle = XP.getCont >>= XP.liftMaybe "dateTime expects text" . XN.getText >>= parseTimeM True defaultTimeLocale fmtz
  }
  where
  fmt = "%0Y-%m-%dT%H:%M:%S%Q"
  fmtz = fmt ++ "%Z"

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

-- |§3.3.20
type NonNegativeInteger = Word

xpNonNegativeInteger :: XP.PU NonNegativeInteger
xpNonNegativeInteger = XP.xpPrim{ XP.theSchema = XPS.scDTxsd XSD.xsd_nonNegativeInteger [] }

-- |§3.3.23
type UnsignedShort = Word16

xpUnsignedShort :: XP.PU UnsignedShort
xpUnsignedShort = XP.xpPrim{ XP.theSchema = XPS.scDTxsd XSD.xsd_unsignedShort [] }
