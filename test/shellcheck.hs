module Main where

import Control.Monad
import System.Exit
import qualified ShellCheck.ASTLib
import qualified ShellCheck.Checks.Safety
import qualified ShellCheck.Parser
import qualified ShellCheck.Safety.Effects
import qualified ShellCheck.Safety.Policy

main = do
    putStrLn "Running ShellCheck tests..."
    failures <- filter (not . snd) <$> mapM sequenceA tests
    if null failures then exitSuccess else do
      putStrLn "Tests failed for the following module(s):"
      mapM (putStrLn . ("- ShellCheck." ++) . fst) failures
      exitFailure
  where
    tests =
      [ ("ASTLib"             , ShellCheck.ASTLib.runTests)
      , ("Checks.Safety"      , ShellCheck.Checks.Safety.runTests)
      , ("Parser"             , ShellCheck.Parser.runTests)
      , ("Safety.Effects"     , ShellCheck.Safety.Effects.runTests)
      , ("Safety.Policy"      , ShellCheck.Safety.Policy.runTests)
      ]
