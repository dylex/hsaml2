-- |
-- XML Schema Datatypes
--
-- <http://www.w3.org/TR/2004/REC-xmlschema-2-20041028/> (selected portions)
module SAML2.XML.Schema.Datatypes where

import Prelude hiding (String)

import qualified Data.ByteString as BS
import qualified Data.Time.Clock as Time
import qualified Network.URI as URI

-- |§3.2.1
type String = [Char]
-- |§3.2.7
type DateTime = Time.UTCTime
-- |§3.2.16
type Base64Binary = BS.ByteString
-- |§3.2.17
type AnyURI = URI.URI
-- |§3.3.8
type ID = String
