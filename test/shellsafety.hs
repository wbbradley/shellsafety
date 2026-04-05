module Main where

import Control.Monad
import System.Exit
import qualified ShellSafety.ASTLib
import qualified ShellSafety.Checker
import qualified ShellSafety.Parser
import qualified ShellSafety.Effects
import qualified ShellSafety.Policy

main = do
    putStrLn "Running ShellSafety tests..."
    failures <- filter (not . snd) <$> mapM sequenceA tests
    if null failures then exitSuccess else do
      putStrLn "Tests failed for the following module(s):"
      mapM (putStrLn . ("- ShellSafety." ++) . fst) failures
      exitFailure
  where
    tests =
      [ ("ASTLib"    , ShellSafety.ASTLib.runTests)
      , ("Checker"   , ShellSafety.Checker.runTests)
      , ("Parser"    , ShellSafety.Parser.runTests)
      , ("Effects"   , ShellSafety.Effects.runTests)
      , ("Policy"    , ShellSafety.Policy.runTests)
      ]
