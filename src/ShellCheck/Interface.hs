{-
    Copyright 2012-2024 Vidar Holen

    This file is part of ShellCheck.
    https://www.shellcheck.net

    ShellCheck is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ShellCheck is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
-}
{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}
module ShellCheck.Interface
    (
    SystemInterface(..)
    , ParseSpec(psFilename, psScript, psCheckSourced, psIgnoreRC, psShellTypeOverride)
    , ParseResult(prComments, prTokenPositions, prRoot)
    , Shell(Ksh, Sh, Bash, Dash, BusyboxSh)
    , ErrorMessage
    , Code
    , Severity(ErrorC, WarningC, InfoC, StyleC)
    , Position(posFile, posLine, posColumn)
    , Comment(cSeverity, cCode, cMessage)
    , PositionedComment(pcStartPos, pcEndPos, pcComment)
    , TokenComment(tcId, tcComment)
    , newParseResult
    , newPosition
    , newSystemInterface
    , newTokenComment
    , mockedSystemInterface
    , newParseSpec
    , newPositionedComment
    , newComment
    ) where

import ShellCheck.AST

import Control.DeepSeq
import Control.Monad.Identity
import Data.List
import GHC.Generics (Generic)
import qualified Data.Map as Map


data SystemInterface m = SystemInterface {
    -- | Given:
    --   What annotations say about including external files (if anything)
    --   A resolved filename from siFindSource
    --   Read the file or return an error
    siReadFile :: Maybe Bool -> String -> m (Either ErrorMessage String),
    -- | Given:
    --   the current script,
    --   what annotations say about including external files (if anything)
    --   a list of source-path annotations in effect,
    --   and a sourced file,
    --   find the sourced file
    siFindSource :: String -> Maybe Bool -> [String] -> String -> m FilePath,
    -- | Get the configuration file (name, contents) for a filename
    siGetConfig :: String -> m (Maybe (FilePath, String))
}

newParseSpec :: ParseSpec
newParseSpec = ParseSpec {
    psFilename = "",
    psScript = "",
    psCheckSourced = False,
    psIgnoreRC = False,
    psShellTypeOverride = Nothing
}

newSystemInterface :: Monad m => SystemInterface m
newSystemInterface =
    SystemInterface {
        siReadFile = \_ _ -> return $ Left "Not implemented",
        siFindSource = \_ _ _ name -> return name,
        siGetConfig = \_ -> return Nothing
    }

-- Parser input and output
data ParseSpec = ParseSpec {
    psFilename :: String,
    psScript :: String,
    psCheckSourced :: Bool,
    psIgnoreRC :: Bool,
    psShellTypeOverride :: Maybe Shell
} deriving (Show, Eq)

data ParseResult = ParseResult {
    prComments :: [PositionedComment],
    prTokenPositions :: Map.Map Id (Position, Position),
    prRoot :: Maybe Token
} deriving (Show, Eq)

newParseResult :: ParseResult
newParseResult = ParseResult {
    prComments = [],
    prTokenPositions = Map.empty,
    prRoot = Nothing
}

-- Supporting data types
data Shell = Ksh | Sh | Bash | Dash | BusyboxSh deriving (Show, Eq)

type ErrorMessage = String
type Code = Integer

data Severity = ErrorC | WarningC | InfoC | StyleC
    deriving (Show, Eq, Ord, Generic, NFData)
data Position = Position {
    posFile :: String,    -- Filename
    posLine :: Integer,   -- 1 based source line
    posColumn :: Integer  -- 1 based source column, where tabs are 8
} deriving (Show, Eq, Generic, NFData, Ord)

newPosition :: Position
newPosition = Position {
    posFile   = "",
    posLine   = 1,
    posColumn = 1
}

data Comment = Comment {
    cSeverity :: Severity,
    cCode     :: Code,
    cMessage  :: String
} deriving (Show, Eq, Generic, NFData)

newComment :: Comment
newComment = Comment {
    cSeverity = StyleC,
    cCode     = 0,
    cMessage  = ""
}

data PositionedComment = PositionedComment {
    pcStartPos :: Position,
    pcEndPos   :: Position,
    pcComment  :: Comment
} deriving (Show, Eq, Generic, NFData)

newPositionedComment :: PositionedComment
newPositionedComment = PositionedComment {
    pcStartPos = newPosition,
    pcEndPos   = newPosition,
    pcComment  = newComment
}

data TokenComment = TokenComment {
    tcId :: Id,
    tcComment :: Comment
} deriving (Show, Eq, Generic, NFData)

newTokenComment = TokenComment {
    tcId = Id 0,
    tcComment = newComment
}

-- For testing
mockedSystemInterface :: [(String, String)] -> SystemInterface Identity
mockedSystemInterface files = (newSystemInterface :: SystemInterface Identity) {
    siReadFile = rf,
    siFindSource = fs,
    siGetConfig = const $ return Nothing
}
  where
    rf _ file = return $
        case find ((== file) . fst) files of
            Nothing -> Left "File not included in mock."
            Just (_, contents) -> Right contents
    fs _ _ _ file = return file
