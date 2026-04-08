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
import ShellSafety.Interface (newParseSpec, ParseSpec(..), newSystemInterface, SystemInterface, ParseResult(..), Shell(..), PositionedComment(..), Comment(..))
import ShellSafety.Parser (parseScript)
import ShellSafety.Analysis (SafetyResult(..), runSafetyM)
import ShellSafety.Policy (Disposition(..), Policy, parsePolicy, policyShell)

import Control.Exception (catch, IOException)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (Value(..), decode)
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import Data.Maybe (fromMaybe)
import Data.Time.Format (formatTime, defaultTimeLocale)
import Data.Time.LocalTime (getZonedTime)
import System.Directory (getHomeDirectory, doesFileExist, getCurrentDirectory)
import System.Environment (getArgs, lookupEnv)
import Data.Version (showVersion)
import Paths_ShellSafety (version)
import System.Exit (exitSuccess, exitFailure)
import System.IO (hPutStrLn, stderr, withFile, IOMode(..), hPutStrLn)
import System.Console.Haskeline

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

data Outcome = Allowed String | Asked String | Denied String | Skipped String

helpText :: String
helpText = unlines
    [ "shellsafety - safety gate for AI agent shell command execution"
    , ""
    , "ShellSafety is a Claude Code PreToolUse hook that parses shell commands,"
    , "classifies their effects, and evaluates them against a policy to allow,"
    , "prompt, or deny execution."
    , ""
    , "SETUP"
    , ""
    , "  1. Create a policy file at ~/.shellsafety:"
    , ""
    , "       assume bash"
    , "       default deny"
    , "       allow effect:readonly"
    , "       allow command:git"
    , "       deny command:git arg:push"
    , ""
    , "  2. Add to ~/.claude/settings.json (or .claude/settings.local.json):"
    , ""
    , "       {"
    , "         \"permissions\": { \"allow\": [\"Bash(*)\"] },"
    , "         \"hooks\": {"
    , "           \"PreToolUse\": [{"
    , "             \"matcher\": \"Bash\","
    , "             \"hooks\": [{ \"type\": \"command\", \"command\": \"shellsafety\" }]"
    , "           }]"
    , "         }"
    , "       }"
    , ""
    , "INTERACTIVE MODE"
    , ""
    , "  shellsafety -i"
    , ""
    , "  Opens a REPL where you can type shell commands and see how the policy"
    , "  would classify them (allow, ask, deny) with reasons."
    , ""
    , "MANUAL TESTING"
    , ""
    , "  Test a denied command:"
    , ""
    , "    echo '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"rm -rf /\"}}' | shellsafety"
    , ""
    , "  Test an allowed command:"
    , ""
    , "    echo '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"ls -la\"}}' | shellsafety"
    , ""
    , "ENVIRONMENT VARIABLES"
    , ""
    , "  SHELLSAFETY_POLICY          Path to policy file (default: ~/.shellsafety)"
    , "  SHELLCHECK_SAFETY_POLICY    Fallback if SHELLSAFETY_POLICY is not set"
    , ""
    , "Full documentation: https://github.com/wbbradley/shellsafety"
    ]

main :: IO ()
main = do
    args <- getArgs
    case args of
        (flag:_) | flag `elem` ["--version", "-V"] -> do
            putStrLn $ "shellsafety " ++ showVersion version
            exitSuccess
        (flag:_) | flag `elem` ["--interactive", "-i"] -> do
            runInteractive
            exitSuccess
        (flag:_) | flag `elem` ["--help", "-h"] -> do
            putStr helpText
            exitSuccess
        _ -> return ()
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
    logInvocation input cmd outcome
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
check policyText cmd =
    case parsePolicy policyText of
        Left err -> do
            hPutStrLn stderr $ "shellsafety: invalid policy: " ++ err
            return (Skipped ("invalid policy: " ++ err), "")
        Right policy -> checkWithPolicy policy cmd

checkWithPolicy :: Policy -> String -> IO (Outcome, String)
checkWithPolicy policy cmd = do
    let script = "#!/bin/bash\n" ++ cmd ++ "\n"
    let shellOverride = policyShell policy >>= shellForExecutable
    let pSpec = newParseSpec {
            psFilename = "script",
            psScript = script,
            psShellTypeOverride = shellOverride
        }
    pr <- parseScript (newSystemInterface :: SystemInterface IO) pSpec
    case prRoot pr of
        Nothing -> do
            let parseErrors = map (cMessage . pcComment) (prComments pr)
            let msg = "Parse failed, defaulting to ask: "
                      ++ if null parseErrors
                         then "(no details)"
                         else unwords parseErrors
            return (Asked msg, askJson msg)
        Just root -> do
            let results = runSafetyM root (checkSafety policy)
            let worst = maximum (Allow : map srDisposition results)
            let relevant = filter ((== worst) . srDisposition) results
            let messages = unlines $ map srMessage relevant
            case worst of
                Allow -> return (Allowed messages, "")
                Ask   -> return (Asked messages, askJson messages)
                Deny  -> return (Denied messages, denyJson messages)

runInteractive :: IO ()
runInteractive = do
    policyPath <- findPolicyFile
    case policyPath of
        Nothing -> do
            hPutStrLn stderr "shellsafety: no policy file found"
            exitFailure
        Just path -> do
            policyResult <- (Right <$> readFile path)
                `catch` (\e -> return $ Left (show (e :: IOException)))
            case policyResult of
                Left err -> do
                    hPutStrLn stderr $ "shellsafety: failed to read policy: " ++ err
                    exitFailure
                Right policyText -> case parsePolicy policyText of
                    Left err -> do
                        hPutStrLn stderr $ "shellsafety: invalid policy: " ++ err
                        exitFailure
                    Right policy -> interactiveLoop policy

interactiveLoop :: Policy -> IO ()
interactiveLoop policy = runInputT defaultSettings loop
  where
    loop = do
        minput <- getInputLine "shellsafety> "
        case minput of
            Nothing -> return ()
            Just cmd | null cmd -> loop
            Just cmd -> do
                (outcome, _) <- liftIO $ checkWithPolicy policy cmd
                let (color, disposition, reasons) = case outcome of
                        Allowed msg -> ("\ESC[32m", "allow", msg)
                        Asked msg   -> ("\ESC[33m", "ask", msg)
                        Denied msg  -> ("\ESC[31m", "deny", msg)
                        Skipped msg -> ("", "skip", msg)
                outputStrLn $ "disposition: " ++ color ++ disposition ++ "\ESC[0m"
                case filter (not . null) (lines reasons) of
                    [] -> return ()
                    rs -> do
                        outputStrLn "reasons:"
                        mapM_ (\r -> outputStrLn $ "  " ++ r) rs
                loop

askJson :: String -> String
askJson reason =
    "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\""
    ++ ",\"permissionDecision\":\"ask\""
    ++ ",\"permissionDecisionReason\":" ++ jsonString reason
    ++ "}}"

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

logInvocation :: BL.ByteString -> Maybe String -> Outcome -> IO ()
logInvocation input cmd outcome = do
    home <- getHomeDirectory
    cwd <- getCurrentDirectory
    now <- getZonedTime
    let ts = formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%S%Q%z" now
    let (decision, reasons) = case outcome of
            Allowed msg  -> ("allow", toReasons msg)
            Asked msg    -> ("ask", toReasons msg)
            Denied msg   -> ("deny", toReasons msg)
            Skipped msg  -> ("skip", [msg])
    let rawInput = map (toEnum . fromEnum) (BL.unpack input) :: String
    let entry = "{" ++ intercalateComma
            [ jsonField "ts" ts
            , jsonField "cwd" cwd
            , jsonField "command" (fromMaybe "" cmd)
            , jsonField "decision" decision
            , jsonArray "reasons" reasons
            , jsonString "input" ++ ":" ++ rawInput
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
