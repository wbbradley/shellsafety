{-
    Copyright 2024 ShellCheck Contributors

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

-- | Claude Code PreToolUse hook binary.
--
-- Reads a hook JSON event from stdin, extracts the Bash command,
-- runs it through shellcheck safety analysis, and returns a
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
--           "hooks": [{ "type": "command", "command": "shellcheck-safety" }]
--         }]
--       }
--     }
--
--   Policy file is read from (in order):
--     1. SHELLCHECK_SAFETY_POLICY environment variable
--     2. ~/.shellsafety

import ShellCheck.Checker
import ShellCheck.Data
import ShellCheck.Interface
import ShellCheck.Safety.Effects (Effect(..), classifyCommand)
import ShellCheck.Safety.Policy (parsePolicy, policyShell, evaluateWithReason)

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

data Outcome = Allowed String | Denied String | Skipped String

main :: IO ()
main = do
    policyPath <- findPolicyFile
    input <- BL.getContents
    let cmd = extractCommand input
    (outcome, output) <- case policyPath of
        Nothing -> do
            hPutStrLn stderr "shellcheck-safety: no policy file found, skipping"
            return (Skipped "no policy file", "")
        Just path -> do
            policyResult <- (Right <$> readFile path)
                `catch` (\e -> return $ Left (show (e :: IOException)))
            case policyResult of
                Left err -> do
                    hPutStrLn stderr $ "shellcheck-safety: failed to read policy: " ++ err
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
    envPath <- lookupEnv "SHELLCHECK_SAFETY_POLICY"
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
    let shellOverride = case parsePolicy policyText of
            Right p -> policyShell p >>= shellForExecutable
            _ -> Nothing
    let spec = emptyCheckSpec {
            csFilename = "-",
            csScript = script,
            csSafetyPolicy = Just policyText,
            csOptionalChecks = ["safety"],
            csShellTypeOverride = shellOverride
        }
    result <- checkScript (newSystemInterface :: SystemInterface IO) spec
    let comments = crComments result
    if null comments
        then return (Allowed (allowReason policyText cmd), "")
        else do
            let messages = unlines $ map formatComment comments
            return (Denied messages, denyJson messages)

formatComment :: PositionedComment -> String
formatComment pc =
    let c = pcComment pc
        code = cCode c
        msg = cMessage c
    in "SC" ++ show code ++ ": " ++ msg

allowReason :: String -> String -> String
allowReason policyText cmd =
    case parsePolicy policyText of
        Left _ -> ""
        Right policy ->
            let baseName = case words cmd of
                    [] -> ""
                    (w:_) -> reverse (takeWhile (/= '/') (reverse w))
                effect = classifyCommand baseName []
                (_, reason) = evaluateWithReason policy baseName [] effect
            in baseName ++ " classified as " ++ show effect ++ ", " ++ reason

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
    let (decision, reason) = case outcome of
            Allowed msg  -> ("allow", msg)
            Denied msg   -> ("deny", msg)
            Skipped msg  -> ("skip", msg)
    let entry = "{" ++ intercalateComma
            [ jsonField "ts" ts
            , jsonField "cwd" cwd
            , jsonField "command" (fromMaybe "" cmd)
            , jsonField "decision" decision
            , jsonField "reason" reason
            ] ++ "}"
    let logPath = home ++ "/shellcheck-safety.log"
    withFile logPath AppendMode (\h -> hPutStrLn h entry)
        `catch` (\e -> hPutStrLn stderr $ "shellcheck-safety: log write failed: " ++ show (e :: IOException))
  where
    jsonField k v = jsonString k ++ ":" ++ jsonString v
    intercalateComma [] = ""
    intercalateComma [x] = x
    intercalateComma (x:xs) = x ++ "," ++ intercalateComma xs
