module Main (main) where

import System.Exit (exitSuccess, exitFailure)
import qualified Test.HUnit as U

import qualified XML.Signature
import qualified XML.Encryption

tests :: U.Test
tests = U.test
  [ U.TestLabel "XML.Signature" XML.Signature.tests
  , U.TestLabel "XML.Encryption" XML.Encryption.tests
  ]

main :: IO ()
main = do
  r <- U.runTestTT tests
  if U.errors r == 0 && U.failures r == 0
    then exitSuccess
    else exitFailure
