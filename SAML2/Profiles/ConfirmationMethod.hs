-- |
-- Confirmation Method Identifiers
-- 
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf saml-profiles-2.0-os> §3
module SAML2.Profiles.ConfirmationMethod where

import qualified SAML2.XML as XML
import qualified SAML2.XML.Signature as DS

-- |§3
data ConfirmationMethod
  = ConfirmationMethodHolderOfKey (XML.List1 DS.KeyInfo)
  | ConfirmationMethodSenderVouches
  | ConfirmationMethodBearer
  | ConfirmationMethod XML.AnyURI
