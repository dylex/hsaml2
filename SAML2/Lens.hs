{-# LANGUAGE TemplateHaskell #-}
module SAML2.Lens
  ( fieldLens
  ) where

import Control.Lens.Lens (lens)
import qualified Language.Haskell.TH as TH

fieldLens :: TH.Name -> TH.ExpQ
fieldLens f = do
  a <- TH.newName "a"
  b <- TH.newName "b"
  return $ TH.VarE 'lens `TH.AppE` TH.VarE f
    `TH.AppE` TH.LamE [TH.VarP a, TH.VarP b] (TH.RecUpdE (TH.VarE a) [(f, TH.VarE b)])
