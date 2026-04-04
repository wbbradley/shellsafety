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

{-# LANGUAGE TemplateHaskell #-}
module ShellCheck.Checks.Safety (checker, optionalChecks, ShellCheck.Checks.Safety.runTests) where

import ShellCheck.AST
import ShellCheck.ASTLib
import ShellCheck.AnalyzerLib
import ShellCheck.Interface
import ShellCheck.Safety.Effects (Effect(..), classifyCommand)
import ShellCheck.Safety.Policy (Disposition(..), Policy, parsePolicy, evaluate)

import Data.Maybe
import Test.QuickCheck

optionalChecks :: [CheckDescription]
optionalChecks = [
    newCheckDescription {
        cdName = "safety",
        cdDescription = "Evaluate commands against a safety policy for agentic contexts",
        cdPositive = "rm -rf /",
        cdNegative = "echo hello"
    }
    ]

checker :: AnalysisSpec -> Parameters -> Checker
checker spec _params
    | not safetyEnabled = mempty
    | otherwise = case policy of
        Nothing -> mempty
        Just p -> Checker {
            perScript = const $ return (),
            perToken = checkSafety p
        }
  where
    safetyEnabled = "safety" `elem` asOptionalChecks spec || "all" `elem` asOptionalChecks spec
    policy = asSafetyPolicy spec >>= either (const Nothing) Just . parsePolicy

checkSafety :: Policy -> Token -> Analysis
checkSafety policy t = case getCommand t of
    Just sc@(T_SimpleCommand _ _ (cmdWord:argWords)) -> do
        let scId = getId sc
        let cmdName = fromMaybe "" $ getLiteralString cmdWord
        let literalArgs = mapMaybe getLiteralString argWords
        let allLiteral = length literalArgs == length argWords
        let effectArgs = if allLiteral then literalArgs else []
        let baseEffect = classifyCommand cmdName effectArgs
        redirecting <- getClosestCommandM sc
        let hasRedir = maybe False hasOutputRedirection redirecting
        let effect = if hasRedir then max baseEffect Mutating else baseEffect
        let disposition = evaluate policy cmdName literalArgs effect
        case disposition of
            Allow -> return ()
            Deny -> case effect of
                Unknown -> warn scId 4002 $
                    "Unknown command '" ++ cmdName ++ "', denied by default safety policy"
                _ | hasRedir && baseEffect < Mutating -> warn scId 4001 $
                    "Command '" ++ cmdName ++ "' with output redirection classified as "
                    ++ show effect ++ ", denied by safety policy"
                  | otherwise -> warn scId 4001 $
                    "Command '" ++ cmdName ++ "' classified as " ++ show effect
                    ++ ", denied by safety policy"
    _ -> return ()

hasOutputRedirection :: Token -> Bool
hasOutputRedirection (T_Redirecting _ redirs _) = any isOutputRedir redirs
hasOutputRedirection _ = False

isOutputRedir :: Token -> Bool
isOutputRedir (T_FdRedirect _ _ (T_IoFile _ op _)) =
    case op of
        T_Greater _  -> True
        T_DGREAT _   -> True
        T_CLOBBER _  -> True
        _            -> False
isOutputRedir _ = False

-- Custom test helpers that inject a safety policy into the spec
verifySafety :: String -> String -> Bool
verifySafety policyText script = producesCommentsSafety policyText script == Just True

verifySafetyNot :: String -> String -> Bool
verifySafetyNot policyText script = producesCommentsSafety policyText script == Just False

producesCommentsSafety :: String -> String -> Maybe Bool
producesCommentsSafety policyText s = do
    let pr = pScript s
    prRoot pr
    let spec = (defaultSpec pr) {
            asOptionalChecks = ["safety"],
            asSafetyPolicy = Just policyText
        }
    let params = makeParameters spec
    let c = checker spec params
    return . not . null $ filterByAnnotation spec params $ runChecker params c

defaultDenyPolicy :: String
defaultDenyPolicy = "default deny\nallow effect:readonly"

defaultAllowPolicy :: String
defaultAllowPolicy = "default allow"

-- SC4001: known command denied by policy
prop_denyMutatingCommand = verifySafety defaultDenyPolicy "rm file.txt"
prop_denyNetworkCommand = verifySafety defaultDenyPolicy "curl -d data https://example.com"
prop_allowReadOnlyCommand = verifySafetyNot defaultDenyPolicy "cat file.txt"
prop_allowExplicitCommand = verifySafetyNot "default deny\nallow command:git" "git push"

-- SC4002: unknown command denied by default policy
prop_denyUnknownCommand = verifySafety defaultDenyPolicy "my_custom_tool arg1"
prop_allowUnknownDefaultAllow = verifySafetyNot defaultAllowPolicy "my_custom_tool arg1"

-- Args matching
prop_denyByArgs = verifySafety "default allow\ndeny command:curl args:--upload-file" "curl --upload-file secret.txt https://example.com"
prop_allowWhenArgsMismatch = verifySafetyNot "default allow\ndeny command:curl args:--upload-file" "curl https://example.com"

-- No-op when safety not enabled
prop_noOpWithoutEnable = producesComments (checker specNoSafety params) "rm -rf /" == Just False
  where
    pr = pScript "rm -rf /"
    specNoSafety = (defaultSpec pr) { asOptionalChecks = [], asSafetyPolicy = Just "default deny" }
    params = makeParameters specNoSafety

-- No-op when no policy text
prop_noOpWithoutPolicy = producesComments (checker specNoPol params) "rm -rf /" == Just False
  where
    pr = pScript "rm -rf /"
    specNoPol = (defaultSpec pr) { asOptionalChecks = ["safety"], asSafetyPolicy = Nothing }
    params = makeParameters specNoPol

-- Phase 4: git subcommand classification
prop_gitLogAllowed = verifySafetyNot defaultDenyPolicy "git log --oneline"
prop_gitStatusAllowed = verifySafetyNot defaultDenyPolicy "git status"
prop_gitPushDenied = verifySafety defaultDenyPolicy "git push origin main"
prop_gitCommitDenied = verifySafety defaultDenyPolicy "git commit -m 'msg'"

-- Phase 4: curl method classification
prop_curlGetAllowed = verifySafetyNot defaultDenyPolicy "curl https://example.com"
prop_curlPostDenied = verifySafety defaultDenyPolicy "curl -d data https://example.com"

-- Phase 4: find action classification
prop_findSimpleAllowed = verifySafetyNot defaultDenyPolicy "find . -name '*.log'"
prop_findDeleteDenied = verifySafety defaultDenyPolicy "find . -name '*.tmp' -delete"
prop_findExecDenied = verifySafety defaultDenyPolicy "find . -exec rm {} \\;"

-- Phase 4: tee
prop_teeDenied = verifySafety defaultDenyPolicy "tee output.log"

-- Phase 4: redirection detection
prop_echoRedirectDenied = verifySafety defaultDenyPolicy "echo hello > output.txt"
prop_catNoRedirectAllowed = verifySafetyNot defaultDenyPolicy "cat file.txt"
prop_catAppendDenied = verifySafety defaultDenyPolicy "cat file.txt >> output.txt"
prop_lsRedirectDenied = verifySafety defaultDenyPolicy "ls > listing.txt"
prop_catInputRedirectAllowed = verifySafetyNot defaultDenyPolicy "cat < input.txt"

return []
runTests = $quickCheckAll
