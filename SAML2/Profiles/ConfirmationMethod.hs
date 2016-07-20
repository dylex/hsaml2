{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
-- |
-- Confirmation Method Identifiers
-- 
-- <https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf saml-profiles-2.0-os> §3
module SAML2.Profiles.ConfirmationMethod where

import SAML2.XML
import SAML2.Core.Namespaces
import SAML2.Core.Versioning

-- |§3
data ConfirmationMethod
  = ConfirmationMethodHolderOfKey
  | ConfirmationMethodSenderVouches
  | ConfirmationMethodBearer
  deriving (Eq, Enum, Bounded, Show)

instance Identifiable URI ConfirmationMethod where
  identifier = samlURNIdentifier "cm" . f where
    f ConfirmationMethodHolderOfKey   = (SAML20, "holder-of-key")
    f ConfirmationMethodSenderVouches = (SAML20, "sender-vouches")
    f ConfirmationMethodBearer        = (SAML20, "bearer")
