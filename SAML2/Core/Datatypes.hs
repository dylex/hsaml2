-- |
-- Common Data Types
--
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf saml-core-2.0-os> §1.3
module SAML2.Core.Datatypes where

import Prelude hiding (String)

import qualified SAML2.XML.Schema.Datatypes as XS

-- |§1.3.1
type XString = XS.String
-- |§1.3.2
type AnyURI = XS.AnyURI
-- |§1.3.3
type DateTime = XS.DateTime
-- |§1.3.4
type ID = XS.ID
-- |§1.3.4
type NCName = XS.NCName
