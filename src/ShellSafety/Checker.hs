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

{-# LANGUAGE TemplateHaskell #-}
module ShellSafety.Checker (checkSafety, ShellSafety.Checker.runTests) where

import ShellSafety.AST
import ShellSafety.ASTLib
import ShellSafety.Interface
import ShellSafety.Analysis (SafetyParams(..), SafetyM, warn, info, getClosestCommandM, pScript, runSafetyAnalysis)
import ShellSafety.Effects (Effect(..), classifyCommand)
import ShellSafety.Policy (Disposition(..), Policy, parsePolicy, evaluate, evaluateWithReason)

import Control.Applicative ((<|>))
import Data.Maybe
import Test.QuickCheck

checkSafety :: Policy -> Token -> SafetyM ()
checkSafety policy t = case t of
    sc@(T_SimpleCommand _ _ (cmdWord:argWords)) -> do
        let scId = getId sc
        case getLiteralString cmdWord of
            Just cmdName -> checkLiteralCommand policy scId cmdName cmdWord argWords sc
            Nothing -> checkDynamicCommand policy scId cmdWord argWords
    _ -> return ()

checkLiteralCommand :: Policy -> Id -> String -> Token -> [Token] -> Token -> SafetyM ()
checkLiteralCommand policy scId cmdName cmdWord argWords sc = do
    let literalArgs = mapMaybe getLiteralString argWords
    let allLiteral = length literalArgs == length argWords
    let effectArgs = if allLiteral then literalArgs else []
    let (effectiveName, baseEffect) = classifyCommand cmdName effectArgs
    redirecting <- getClosestCommandM sc
    let hasRedir = maybe False hasOutputRedirection redirecting
    let effect = if hasRedir then max baseEffect Mutating else baseEffect
    let displayName = if effectiveName /= cmdName
                      then "'" ++ effectiveName ++ "' (via " ++ cmdName ++ ")"
                      else "'" ++ effectiveName ++ "'"
    let (disposition, reason) = evaluateWithReason policy cmdName literalArgs effect
    case disposition of
        Allow -> info scId 4000 $
            "Command " ++ displayName ++ " classified as " ++ show effect
            ++ ", allowed by safety policy (" ++ reason ++ ")"
        Ask -> case effect of
            Unknown -> warn scId 4004 $
                "Unknown command " ++ displayName ++ ", ask per safety policy"
            _ | hasRedir && baseEffect < Mutating -> warn scId 4003 $
                "Command " ++ displayName ++ " with output redirection classified as "
                ++ show effect ++ ", ask per safety policy"
              | otherwise -> warn scId 4003 $
                "Command " ++ displayName ++ " classified as " ++ show effect
                ++ ", ask per safety policy"
        Deny -> case effect of
            Unknown -> warn scId 4002 $
                "Unknown command " ++ displayName ++ ", denied by default safety policy"
            _ | hasRedir && baseEffect < Mutating -> warn scId 4001 $
                "Command " ++ displayName ++ " with output redirection classified as "
                ++ show effect ++ ", denied by safety policy"
              | otherwise -> warn scId 4001 $
                "Command " ++ displayName ++ " classified as " ++ show effect
                ++ ", denied by safety policy"

checkDynamicCommand :: Policy -> Id -> Token -> [Token] -> SafetyM ()
checkDynamicCommand policy scId cmdWord argWords = do
    let literalArgs = mapMaybe getLiteralString argWords
    let innerName = getCommandNameFromExpansion cmdWord
            <|> getVarExpansionName cmdWord
    let innerDesc = case innerName of
            Just name -> "Dynamic command (inner: " ++ name ++ ")"
            Nothing   -> "Dynamic command"
    let (disposition, _reason) = evaluateWithReason policy "" literalArgs Dynamic
    case disposition of
        Allow -> info scId 4000 $
            innerDesc ++ ", allowed by safety policy"
        Ask -> warn scId 4006 $
            innerDesc ++ ", ask per safety policy"
        Deny -> warn scId 4005 $
            innerDesc ++ ", denied by safety policy"

-- | Try to extract a variable name from $VAR used as a command name.
getVarExpansionName :: Token -> Maybe String
getVarExpansionName t = case getWordParts t of
    (T_DollarBraced _ _ _):_ -> Just "$VAR"
    _ -> Nothing

hasOutputRedirection :: Token -> Bool
hasOutputRedirection (T_Redirecting _ redirs _) = any isOutputRedir redirs
hasOutputRedirection _ = False

isOutputRedir :: Token -> Bool
isOutputRedir (T_FdRedirect _ _ (T_IoFile _ op file))
    | not (isDevNull file) =
        case op of
            T_Greater _  -> True
            T_DGREAT _   -> True
            T_CLOBBER _  -> True
            _            -> False
isOutputRedir _ = False

isDevNull :: Token -> Bool
isDevNull t = getLiteralString t == Just "/dev/null"

-- Custom test helpers that inject a safety policy into the spec
verifySafety :: String -> String -> Bool
verifySafety policyText script = producesCommentsSafety policyText script == Just True

verifySafetyNot :: String -> String -> Bool
verifySafetyNot policyText script = producesCommentsSafety policyText script == Just False

producesCommentsSafety :: String -> String -> Maybe Bool
producesCommentsSafety policyText s =
    case parsePolicy policyText of
        Left _ -> Nothing
        Right p -> do
            comments <- runSafetyAnalysis (checkSafety p) s
            return . not . null $ filter (\tc -> cCode (tcComment tc) /= 4000) comments

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
prop_denyByArgs = verifySafety "default allow\ndeny command:curl arg:--upload-file" "curl --upload-file secret.txt https://example.com"
prop_allowWhenArgsMismatch = verifySafetyNot "default allow\ndeny command:curl arg:--upload-file" "curl https://example.com"

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
prop_stderrToDevNullAllowed = verifySafetyNot defaultDenyPolicy "cat file.txt 2>/dev/null"
prop_stdoutToDevNullAllowed = verifySafetyNot defaultDenyPolicy "echo hello > /dev/null"
prop_stderrToFileStillDenied = verifySafety defaultDenyPolicy "cat file.txt 2> errors.log"

-- Phase 5: arg regex integration
prop_denyByArgRegex = verifySafety "default allow\ndeny command:curl arg:/-[dFT]/" "curl -d data https://example.com"
prop_allowWhenArgRegexMismatch = verifySafetyNot "default allow\ndeny command:curl arg:/-[dFT]/" "curl https://example.com"

-- Phase 6: compound construct coverage
prop_pipelineBothChecked = verifySafety defaultDenyPolicy "cat file.txt | tee output.log"
prop_pipelineAllowedIfBothSafe = verifySafetyNot defaultDenyPolicy "cat file.txt | grep pattern"
prop_commandSubstitution = verifySafety defaultDenyPolicy "echo $(rm file.txt)"
prop_subshell = verifySafety defaultDenyPolicy "(rm file.txt)"
prop_commandGroup = verifySafety defaultDenyPolicy "{ rm file.txt; }"
prop_backgroundCommand = verifySafety defaultDenyPolicy "rm file.txt &"
prop_ifConditionChecked = verifySafety defaultDenyPolicy "if rm file.txt; then echo done; fi"
prop_whileConditionChecked = verifySafety defaultDenyPolicy "while rm file.txt; do echo loop; done"

-- Phase 6: curl --flag=value integration
prop_curlDataEqualsIntegration = verifySafety defaultDenyPolicy "curl --data=hello https://example.com"

-- Ask disposition tests
verifySafetyAsk :: String -> String -> Bool
verifySafetyAsk policyText script = producesAskCodes policyText script == Just True

verifySafetyNotAsk :: String -> String -> Bool
verifySafetyNotAsk policyText script = producesAskCodes policyText script == Just False

producesAskCodes :: String -> String -> Maybe Bool
producesAskCodes policyText s =
    case parsePolicy policyText of
        Left _ -> Nothing
        Right p -> do
            comments <- runSafetyAnalysis (checkSafety p) s
            return . not . null $ filter (\tc -> cCode (tcComment tc) `elem` [4003, 4004, 4006]) comments

defaultAskPolicy :: String
defaultAskPolicy = "default ask\nallow effect:readonly"

prop_askMutatingCommand = verifySafetyAsk defaultAskPolicy "rm file.txt"
prop_askUnknownCommand = verifySafetyAsk "default ask" "my_custom_tool arg1"
prop_askReadOnlyAllowed = verifySafetyNotAsk defaultAskPolicy "cat file.txt"

-- Dynamic command tests
prop_dynamicCommandDenied = verifySafety defaultDenyPolicy "$(my_tool) arg1"
prop_dynamicCommandAllowed = verifySafetyNot "default deny\nallow effect:dynamic\nallow effect:unknown" "$(my_tool) arg1"
prop_dynamicCommandAsk = verifySafetyAsk "default ask\nallow effect:readonly" "$(my_tool) arg1"

-- xargs argument-aware integration tests
prop_xargsGrepAllowed = verifySafetyNot defaultDenyPolicy "echo files | xargs grep foo"
prop_xargsRmDenied = verifySafety defaultDenyPolicy "echo files | xargs rm"
prop_xargsMvDenied = verifySafety defaultDenyPolicy "echo files | xargs -0 -I {} mv {} {}.bak"
prop_xargsCurlNoDenied = verifySafety defaultDenyPolicy "echo urls | xargs curl"
prop_xargsBareAllowed = verifySafetyNot defaultDenyPolicy "echo hello | xargs"
prop_xargsComplexFlagsUnknown = verifySafety defaultDenyPolicy "echo | xargs -I XX -n 3 my-cmd XX"

return []
runTests = $quickCheckAll
