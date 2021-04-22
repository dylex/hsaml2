module XML.Keys (privkey1, pubkey1, pubkey2) where

import SAML2.XML.Signature
import qualified Crypto.PubKey.DSA as DSA
import System.IO.Unsafe (unsafePerformIO)

{-# NOINLINE keypair1 #-}
keypair1 :: (SigningKey, PublicKeys)
keypair1 = unsafePerformIO mkkeypair

{-# NOINLINE keypair2 #-}
keypair2 :: (SigningKey, PublicKeys)
keypair2 = unsafePerformIO mkkeypair

privkey1, _privkey2 :: SigningKey
pubkey1, pubkey2 :: PublicKeys
((privkey1, pubkey1), (_privkey2, pubkey2)) = (keypair1, keypair2)

mkkeypair :: IO (SigningKey, PublicKeys)
mkkeypair = do
  privnum <- DSA.generatePrivate params
  let pubnum = DSA.calculatePublic params privnum
      kp = DSA.KeyPair params pubnum privnum
  pure (SigningKeyDSA kp, PublicKeys (Just $ DSA.toPublicKey kp) Nothing)
  where
    params = DSA.Params
      { DSA.params_p = 13232376895198612407547930718267435757728527029623408872245156039757713029036368719146452186041204237350521785240337048752071462798273003935646236777459223
      , DSA.params_q = 857393771208094202104259627990318636601332086981
      , DSA.params_g = 5421644057436475141609648488325705128047428394380474376834667300766108262613900542681289080713724597310673074119355136085795982097390670890367185141189796
      }

