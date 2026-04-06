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

-- | Claude Code PreToolUse hook binary.
--
-- Reads a hook JSON event from stdin, extracts the Bash command,
-- runs it through shellsafety analysis, and returns a
-- deny decision if the command violates the safety policy.
--
-- Usage:
--   Install as a Claude Code PreToolUse hook in .claude/settings.json:
--
--     {
--       "permissions": { "allow": ["Bash(*)"] },
--       "hooks": {
--         "PreToolUse": [{
--           "matcher": "Bash",
--           "hooks": [{ "type": "command", "command": "shellsafety" }]
--         }]
--       }
--     }
--
--   Policy file is read from (in order):
--     1. SHELLSAFETY_POLICY environment variable (fallback: SHELLCHECK_SAFETY_POLICY)
--     2. ~/.shellsafety

import ShellSafety.Checker (checkSafety)
import ShellSafety.Interface (TokenComment(..), Comment(..), newParseSpec, ParseSpec(..), newSystemInterface, SystemInterface, ParseResult(..), Shell(..))
import ShellSafety.Parser (parseScript)
import ShellSafety.Analysis (runSafetyM)
import ShellSafety.Policy (parsePolicy, policyShell)

import Control.Exception (catch, IOException)
import Data.Aeson (Value(..), decode)
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import Data.Maybe (fromMaybe)
import Data.Time.Format (formatTime, defaultTimeLocale)
import Data.Time.Clock (getCurrentTime)
import System.Directory (getHomeDirectory, doesFileExist, getCurrentDirectory)
import System.Environment (lookupEnv)
import System.Exit (exitSuccess)
import System.IO (hPutStrLn, stderr, withFile, IOMode(..), hPutStrLn)

shellForExecutable :: String -> Maybe Shell
shellForExecutable name =
    case name of
        "sh"    -> return Sh
        "bash"  -> return Bash
        "bats"  -> return Bash
        "busybox"    -> return BusyboxSh
        "busybox sh" -> return BusyboxSh
        "busybox ash" -> return BusyboxSh
        "dash"  -> return Dash
        "ash"   -> return Dash
        "ksh"   -> return Ksh
        "ksh88" -> return Ksh
        "ksh93" -> return Ksh
        "oksh"  -> return Ksh
        _ -> Nothing

data Outcome = Allowed String | Denied String | Skipped String

main :: IO ()
main = do
    policyPath <- findPolicyFile
    input <- BL.getContents
    let cmd = extractCommand input
    (outcome, output) <- case policyPath of
        Nothing -> do
            hPutStrLn stderr "shellsafety: no policy file found, skipping"
            return (Skipped "no policy file", "")
        Just path -> do
            policyResult <- (Right <$> readFile path)
                `catch` (\e -> return $ Left (show (e :: IOException)))
            case policyResult of
                Left err -> do
                    hPutStrLn stderr $ "shellsafety: failed to read policy: " ++ err
                    return (Skipped ("failed to read policy: " ++ err), "")
                Right policyText -> case cmd of
                    Nothing -> return (Skipped "no command in input", "")
                    Just c -> check policyText c
    logInvocation cmd outcome
    case output of
        "" -> return ()
        s  -> putStr s
    exitSuccess

findPolicyFile :: IO (Maybe FilePath)
findPolicyFile = do
    envPath <- lookupEnv "SHELLSAFETY_POLICY"
    envPath <- case envPath of
        Just _ -> return envPath
        Nothing -> lookupEnv "SHELLCHECK_SAFETY_POLICY"
    case envPath of
        Just p -> do
            exists <- doesFileExist p
            return $ if exists then Just p else Nothing
        Nothing -> do
            home <- getHomeDirectory
            let defaultPath = home ++ "/.shellsafety"
            exists <- doesFileExist defaultPath
            return $ if exists then Just defaultPath else Nothing

extractCommand :: BL.ByteString -> Maybe String
extractCommand input = do
    Object top <- decode input
    Object toolInput <- KM.lookup (Key.fromString "tool_input") top
    String cmd <- KM.lookup (Key.fromString "command") toolInput
    return $ T.unpack cmd

check :: String -> String -> IO (Outcome, String)
check policyText cmd = do
    let script = "#!/bin/bash\n" ++ cmd ++ "\n"
    case parsePolicy policyText of
        Left err -> do
            hPutStrLn stderr $ "shellsafety: invalid policy: " ++ err
            return (Skipped ("invalid policy: " ++ err), "")
        Right policy -> do
            let shellOverride = policyShell policy >>= shellForExecutable
            let pSpec = newParseSpec {
                    psFilename = "script",
                    psScript = script,
                    psShellTypeOverride = shellOverride
                }
            pr <- parseScript (newSystemInterface :: SystemInterface IO) pSpec
            case prRoot pr of
                Nothing -> return (Skipped "parse failed", "")
                Just root -> do
                    let comments = runSafetyM root (checkSafety policy)
                    let denies = filter (isDeny . tcComment) comments
                    let allows = filter (isAllow . tcComment) comments
                    let allowMessages = unlines $ map formatComment allows
                    if null denies
                        then return (Allowed allowMessages, "")
                        else do
                            let denyMessages = unlines $ map formatComment denies
                            return (Denied denyMessages, denyJson denyMessages)
  where
    isDeny c = cCode c `elem` [4001, 4002]
    isAllow c = cCode c == 4000

formatComment :: TokenComment -> String
formatComment tc =
    let c = tcComment tc
        code = cCode c
        msg = cMessage c
    in "SC" ++ show code ++ ": " ++ msg

denyJson :: String -> String
denyJson reason =
    "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\""
    ++ ",\"permissionDecision\":\"deny\""
    ++ ",\"permissionDecisionReason\":" ++ jsonString reason
    ++ "}}"

jsonString :: String -> String
jsonString s = "\"" ++ concatMap escape s ++ "\""
  where
    escape '"'  = "\\\""
    escape '\\' = "\\\\"
    escape '\n' = "\\n"
    escape '\r' = "\\r"
    escape '\t' = "\\t"
    escape c    = [c]

logInvocation :: Maybe String -> Outcome -> IO ()
logInvocation cmd outcome = do
    home <- getHomeDirectory
    cwd <- getCurrentDirectory
    now <- getCurrentTime
    let ts = formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%S%QZ" now
    let (decision, reasons) = case outcome of
            Allowed msg  -> ("allow", toReasons msg)
            Denied msg   -> ("deny", toReasons msg)
            Skipped msg  -> ("skip", [msg])
    let entry = "{" ++ intercalateComma
            [ jsonField "ts" ts
            , jsonField "cwd" cwd
            , jsonField "command" (fromMaybe "" cmd)
            , jsonField "decision" decision
            , jsonArray "reasons" reasons
            ] ++ "}"
    let logPath = home ++ "/shellsafety.log"
    withFile logPath AppendMode (\h -> hPutStrLn h entry)
        `catch` (\e -> hPutStrLn stderr $ "shellsafety: log write failed: " ++ show (e :: IOException))
  where
    toReasons s = filter (not . null) (lines s)
    jsonField k v = jsonString k ++ ":" ++ jsonString v
    jsonArray k vs = jsonString k ++ ":[" ++ intercalateComma (map jsonString vs) ++ "]"
    intercalateComma [] = ""
    intercalateComma [x] = x
    intercalateComma (x:xs) = x ++ "," ++ intercalateComma xs
