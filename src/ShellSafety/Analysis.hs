{-
    Copyright 2024-2026 Will Bradley

    This file is part of ShellSafety.
    https://github.com/wbbradley/shellsafety

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

{-# LANGUAGE FlexibleContexts #-}
module ShellSafety.Analysis
    (
    -- * Types
      SafetyParams(..)
    , SafetyM

    -- * Comment helpers
    , makeComment
    , addComment
    , warn
    , info

    -- * Parent traversal
    , getParentTree
    , getClosestCommand
    , getClosestCommandM
    , findFirst

    -- * Runner
    , runSafetyM

    -- * Test helpers
    , pScript
    , runSafetyAnalysis
    ) where

import ShellSafety.AST
import ShellSafety.ASTLib
import ShellSafety.Interface
import ShellSafety.Parser

import Control.Arrow (first)
import Control.DeepSeq
import Control.Monad
import Control.Monad.Identity
import Control.Monad.RWS
import Control.Monad.State
import Control.Monad.Writer
import qualified Data.List.NonEmpty as NE
import qualified Data.Map as Map


-- | Lightweight parameters for safety analysis.
-- Unlike AnalyzerLib.Parameters, this does not include variableFlow,
-- cfgAnalysis, or any of the other heavyweight analysis state.
data SafetyParams = SafetyParams
    { spParentMap :: Map.Map Id Token
    , spRootNode  :: Token
    } deriving (Show)

-- | The safety analysis monad. Reader for params, Writer for comments, no state needed.
type SafetyM = RWS SafetyParams [TokenComment] ()


-- Comment helpers (from AnalyzerLib)

makeComment :: Severity -> Id -> Code -> String -> TokenComment
makeComment severity id code note =
    newTokenComment {
        tcId = id,
        tcComment = newComment {
            cSeverity = severity,
            cCode = code,
            cMessage = note
        }
    }

addComment :: MonadWriter [TokenComment] m => TokenComment -> m ()
addComment note = note `deepseq` tell [note]

warn :: MonadWriter [TokenComment] m => Id -> Code -> String -> m ()
warn id code str = addComment $ makeComment WarningC id code str

info :: MonadWriter [TokenComment] m => Id -> Code -> String -> m ()
info id code str = addComment $ makeComment InfoC id code str


-- Parent traversal (from AnalyzerLib)

-- | Build a map from token Id to parent Token.
getParentTree :: Token -> Map.Map Id Token
getParentTree t =
    snd $ execState (doStackAnalysis pre post t) ([], Map.empty)
  where
    pre t = modify (first ((:) t))
    post t = do
        (x, map) <- get
        case x of
          _:rest -> case rest of []    -> put (rest, map)
                                 (x:_) -> put (rest, Map.insert (getId t) x map)

-- | Get the parent command (T_Redirecting) of a Token, if any.
getClosestCommand :: Map.Map Id Token -> Token -> Maybe Token
getClosestCommand tree t =
    findFirst findCommand $ NE.toList $ getPath tree t
  where
    findCommand t =
        case t of
            T_Redirecting {} -> return True
            T_Script {}      -> return False
            _                -> Nothing

-- | Monadic version of getClosestCommand using SafetyParams.
getClosestCommandM :: Token -> SafetyM (Maybe Token)
getClosestCommandM t = do
    params <- ask
    return $ getClosestCommand (spParentMap params) t

-- | Find the first match in a list where the predicate is Just True.
-- Stops if it's Just False and ignores Nothing.
findFirst :: (a -> Maybe Bool) -> [a] -> Maybe a
findFirst p = foldr go Nothing
  where
    go x acc =
      case p x of
        Just True  -> return x
        Just False -> Nothing
        Nothing    -> acc


-- Runner

-- | Run a safety analysis over an AST. Builds SafetyParams from the root token,
-- walks the AST with doAnalysis, and returns collected comments.
runSafetyM :: Token -> (Token -> SafetyM ()) -> [TokenComment]
runSafetyM root check =
    snd $ evalRWS (void $ doAnalysis check root) params ()
  where
    params = SafetyParams
        { spParentMap = getParentTree root
        , spRootNode  = root
        }


-- Test helpers

-- | Parse a script string for testing.
pScript :: String -> ParseResult
pScript s =
    let pSpec = newParseSpec { psFilename = "script", psScript = s }
    in runIdentity $ parseScript (mockedSystemInterface []) pSpec

-- | Parse a script and run a safety check over it. Returns Nothing if parse
-- fails, otherwise Just the list of comments.
--
-- Deliberately omits filterByAnnotation: SC4xxx safety codes must never be
-- suppressible via annotations.
runSafetyAnalysis :: (Token -> SafetyM ()) -> String -> Maybe [TokenComment]
runSafetyAnalysis check s = do
    root <- prRoot (pScript s)
    return $ runSafetyM root check
