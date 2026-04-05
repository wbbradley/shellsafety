{-
    Copyright 2024-2026 Will Bradley

    This file is part of ShellSafety.
    https://github.com/wbbradley/shellcheck

    ShellSafety is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ShellSafety is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
-}

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
