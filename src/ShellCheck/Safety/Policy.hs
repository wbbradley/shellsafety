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
module ShellCheck.Safety.Policy (
    Disposition(..),
    Matcher(..),
    Rule(..),
    Policy(..),
    parsePolicy,
    evaluate,
    evaluateWithReason,
    runTests
    ) where

import Data.Char (isSpace, toLower)
import Data.List (isInfixOf, isPrefixOf)
import ShellCheck.Regex (matches)
import ShellCheck.Safety.Effects (Effect(..))
import Test.QuickCheck
import Text.Regex.TDFA (Regex, makeRegexM)

data Disposition = Allow | Deny deriving (Eq, Show)

data Matcher
    = MatchEffect Effect
    | MatchCommand String
    | MatchArgExact String
    | MatchArgRegex String Regex

instance Eq Matcher where
    MatchEffect a    == MatchEffect b    = a == b
    MatchCommand a   == MatchCommand b   = a == b
    MatchArgExact a  == MatchArgExact b  = a == b
    MatchArgRegex a _ == MatchArgRegex b _ = a == b
    _ == _ = False

instance Show Matcher where
    show (MatchEffect e)    = "MatchEffect " ++ show e
    show (MatchCommand c)   = "MatchCommand " ++ show c
    show (MatchArgExact w)  = "MatchArgExact " ++ show w
    show (MatchArgRegex p _) = "MatchArgRegex " ++ show p

data Rule = Rule Disposition [Matcher] deriving (Eq, Show)

data Policy = Policy {
    policyDefault :: Disposition,
    policyRules :: [Rule],
    policyShell :: Maybe String
} deriving (Eq, Show)

parsePolicy :: String -> Either String Policy
parsePolicy input = do
    let numbered = zip [1..] (lines input)
    let nonEmpty = filter (not . isBlankOrComment . snd) numbered
    foldl (\acc item -> acc >>= \p -> parseLine p item) (Right (Policy Deny [] Nothing)) nonEmpty
  where
    isBlankOrComment s = all isSpace s || "#" `isPrefixOf` dropWhile isSpace s

parseLine :: Policy -> (Int, String) -> Either String Policy
parseLine policy (lineNum, line) =
    case words line of
        ("default" : rest) -> parseDefault policy lineNum rest
        ("allow" : rest) -> parseRule policy lineNum Allow rest
        ("deny" : rest) -> parseRule policy lineNum Deny rest
        ["assume", shell] -> Right policy { policyShell = Just (map toLower shell) }
        ("assume" : _) -> Left $ "line " ++ show lineNum ++ ": expected 'assume <shell>' (e.g. 'assume bash')"
        _ -> Left $ "line " ++ show lineNum ++ ": expected 'default', 'allow', 'deny', or 'assume'"

parseDefault :: Policy -> Int -> [String] -> Either String Policy
parseDefault policy lineNum ws =
    case ws of
        ["allow"] -> Right policy { policyDefault = Allow }
        ["deny"] -> Right policy { policyDefault = Deny }
        _ -> Left $ "line " ++ show lineNum ++ ": expected 'default allow' or 'default deny'"

parseRule :: Policy -> Int -> Disposition -> [String] -> Either String Policy
parseRule policy lineNum disp tokens = do
    matchers <- mapM (parseMatcher lineNum) tokens
    Right policy { policyRules = policyRules policy ++ [Rule disp matchers] }

parseMatcher :: Int -> String -> Either String Matcher
parseMatcher lineNum token =
    case break (== ':') token of
        ("command", ':' : name) -> Right $ MatchCommand name
        ("effect", ':' : name) -> case parseEffect name of
            Just e -> Right $ MatchEffect e
            Nothing -> Left $ "line " ++ show lineNum ++ ": unknown effect '" ++ name ++ "'"
        ("arg", ':' : pat) -> parseArgMatcher lineNum pat
        _ -> Left $ "line " ++ show lineNum ++ ": invalid matcher '" ++ token ++ "'"

parseArgMatcher :: Int -> String -> Either String Matcher
parseArgMatcher lineNum pat
    | isRegex pat =
        let inner = init (tail pat)
        in case makeRegexM inner of
            Just re -> Right $ MatchArgRegex inner re
            Nothing -> Left $ "line " ++ show lineNum
                ++ ": invalid regex in arg matcher: '" ++ inner ++ "'"
    | otherwise = Right $ MatchArgExact pat
  where
    isRegex s = length s >= 2 && head s == '/' && last s == '/'

parseEffect :: String -> Maybe Effect
parseEffect s = case map toLower s of
    "readonly" -> Just ReadOnly
    "mutating" -> Just Mutating
    "network_out" -> Just NetworkOut
    "executing" -> Just Executing
    "unknown" -> Just Unknown
    _ -> Nothing

evaluate :: Policy -> String -> [String] -> Effect -> Disposition
evaluate policy cmd args effect = fst (evaluateWithReason policy cmd args effect)

evaluateWithReason :: Policy -> String -> [String] -> Effect -> (Disposition, String)
evaluateWithReason policy cmd args effect =
    case filter (ruleMatches cmd args effect) (policyRules policy) of
        [] -> (policyDefault policy, "default " ++ map toLower (show (policyDefault policy)))
        rs -> (ruleDisposition (last rs), showRule (last rs))

ruleDisposition :: Rule -> Disposition
ruleDisposition (Rule d _) = d

showRule :: Rule -> String
showRule (Rule d ms) = map toLower (show d) ++ concatMap (\m -> " " ++ showMatcher m) ms

showMatcher :: Matcher -> String
showMatcher (MatchEffect e) = "effect:" ++ map toLower (show e)
showMatcher (MatchCommand c) = "command:" ++ c
showMatcher (MatchArgExact w) = "arg:" ++ w
showMatcher (MatchArgRegex p _) = "arg:/" ++ p ++ "/"

ruleMatches :: String -> [String] -> Effect -> Rule -> Bool
ruleMatches cmd args effect (Rule _ matchers) = all matchOne matchers
  where
    matchOne (MatchEffect e) = effect == e
    matchOne (MatchCommand c) = cmd == c
    matchOne (MatchArgExact word) = word `elem` args
    matchOne (MatchArgRegex _ re) = any (`matches` re) args

-- Tests

prop_parseEmpty :: Bool
prop_parseEmpty = parsePolicy "" == Right (Policy Deny [] Nothing)

prop_parseComments :: Bool
prop_parseComments = parsePolicy "# this is a comment\n  # indented comment\n" == Right (Policy Deny [] Nothing)

prop_parseDefaultAllow :: Bool
prop_parseDefaultAllow = case parsePolicy "default allow" of
    Right p -> policyDefault p == Allow
    _ -> False

prop_parseDefaultDeny :: Bool
prop_parseDefaultDeny = case parsePolicy "default deny" of
    Right p -> policyDefault p == Deny
    _ -> False

prop_parseAllowCommand :: Bool
prop_parseAllowCommand = case parsePolicy "allow command:ls" of
    Right p -> policyRules p == [Rule Allow [MatchCommand "ls"]]
    _ -> False

prop_parseDenyEffect :: Bool
prop_parseDenyEffect = case parsePolicy "deny effect:executing" of
    Right p -> policyRules p == [Rule Deny [MatchEffect Executing]]
    _ -> False

prop_parseMultipleMatchers :: Bool
prop_parseMultipleMatchers = case parsePolicy "deny command:rm arg:-rf" of
    Right p -> policyRules p == [Rule Deny [MatchCommand "rm", MatchArgExact "-rf"]]
    _ -> False

prop_parseMultipleRules :: Bool
prop_parseMultipleRules = case parsePolicy "allow effect:readonly\ndeny command:rm" of
    Right p -> policyRules p == [Rule Allow [MatchEffect ReadOnly], Rule Deny [MatchCommand "rm"]]
    _ -> False

prop_parseInvalidLine :: Bool
prop_parseInvalidLine = case parsePolicy "gibberish nonsense" of
    Left msg -> "line 1" `isInfixOf` msg
    _ -> False

prop_parseInvalidEffect :: Bool
prop_parseInvalidEffect = case parsePolicy "deny effect:bogus" of
    Left msg -> "line 1" `isInfixOf` msg
    _ -> False

prop_evalDefaultDeny :: Bool
prop_evalDefaultDeny =
    evaluate (Policy Deny [] Nothing) "foo" [] Unknown == Deny

prop_evalDefaultAllow :: Bool
prop_evalDefaultAllow =
    evaluate (Policy Allow [] Nothing) "foo" [] Unknown == Allow

prop_evalAllowByEffect :: Bool
prop_evalAllowByEffect =
    let Right p = parsePolicy "default deny\nallow effect:readonly"
    in evaluate p "cat" [] ReadOnly == Allow

prop_evalDenyByCommand :: Bool
prop_evalDenyByCommand =
    let Right p = parsePolicy "default allow\ndeny command:rm"
    in evaluate p "rm" [] Mutating == Deny

prop_evalAllowByCommand :: Bool
prop_evalAllowByCommand =
    let Right p = parsePolicy "default deny\nallow command:git"
    in evaluate p "git" [] Mutating == Allow

prop_evalLastMatchWins :: Bool
prop_evalLastMatchWins =
    let Right p = parsePolicy "allow command:rm\ndeny command:rm"
    in evaluate p "rm" [] Mutating == Deny

prop_evalArgsMatcher :: Bool
prop_evalArgsMatcher =
    let Right p = parsePolicy "default allow\ndeny command:curl arg:--upload-file"
    in evaluate p "curl" ["--upload-file", "secret.txt"] NetworkOut == Deny

prop_evalArgsNoMatch :: Bool
prop_evalArgsNoMatch =
    let Right p = parsePolicy "default allow\ndeny command:curl arg:--upload-file"
    in evaluate p "curl" ["https://example.com"] NetworkOut == Allow

prop_evalMultiMatcherAllRequired :: Bool
prop_evalMultiMatcherAllRequired =
    let Right p = parsePolicy "default allow\ndeny command:rm arg:-rf"
    in evaluate p "rm" ["file.txt"] Mutating == Allow
       && evaluate p "rm" ["-rf", "/"] Mutating == Deny

prop_evalEffectNameCase :: Bool
prop_evalEffectNameCase =
    let Right p = parsePolicy "allow effect:ReadOnly"
    in evaluate p "cat" [] ReadOnly == Allow

prop_parseAssumeBash :: Bool
prop_parseAssumeBash = case parsePolicy "assume bash" of
    Right p -> policyShell p == Just "bash"
    _ -> False

prop_parseAssumeSh :: Bool
prop_parseAssumeSh = case parsePolicy "assume sh" of
    Right p -> policyShell p == Just "sh"
    _ -> False

prop_parseAssumeCaseInsensitive :: Bool
prop_parseAssumeCaseInsensitive = case parsePolicy "assume BASH" of
    Right p -> policyShell p == Just "bash"
    _ -> False

prop_parseNoAssume :: Bool
prop_parseNoAssume = case parsePolicy "default deny" of
    Right p -> policyShell p == Nothing
    _ -> False

prop_parseAssumeInvalidNoArgs :: Bool
prop_parseAssumeInvalidNoArgs = case parsePolicy "assume" of
    Left _ -> True
    _ -> False

-- Phase 5: arg exact matching
prop_parseArgExact :: Bool
prop_parseArgExact = case parsePolicy "deny arg:push" of
    Right p -> case policyRules p of
        [Rule Deny [MatchArgExact "push"]] -> True
        _ -> False
    _ -> False

prop_evalArgExactMatch :: Bool
prop_evalArgExactMatch =
    let Right p = parsePolicy "default allow\ndeny arg:push"
    in evaluate p "git" ["push", "origin"] Mutating == Deny

prop_evalArgExactNoSubstring :: Bool
prop_evalArgExactNoSubstring =
    let Right p = parsePolicy "default allow\ndeny arg:rf"
    in evaluate p "rm" ["-rf"] Mutating == Allow

-- Phase 5: arg regex matching
prop_parseArgRegex :: Bool
prop_parseArgRegex = case parsePolicy "deny arg:/^push$/" of
    Right p -> case policyRules p of
        [Rule Deny [MatchArgRegex "^push$" _]] -> True
        _ -> False
    _ -> False

prop_parseArgRegexInvalid :: Bool
prop_parseArgRegexInvalid = case parsePolicy "deny arg:/[invalid/" of
    Left msg -> "line 1" `isInfixOf` msg
    _ -> False

prop_evalArgRegexMatch :: Bool
prop_evalArgRegexMatch =
    let Right p = parsePolicy "default allow\ndeny arg:/^-[dFT]$/"
    in evaluate p "curl" ["-d", "data"] NetworkOut == Deny

prop_evalArgRegexSubstring :: Bool
prop_evalArgRegexSubstring =
    let Right p = parsePolicy "default allow\ndeny arg:/drive/"
    in evaluate p "cmd" ["--drive=/foo"] Unknown == Deny

prop_evalArgRegexNoMatch :: Bool
prop_evalArgRegexNoMatch =
    let Right p = parsePolicy "default allow\ndeny arg:/^push$/"
    in evaluate p "git" ["pull"] Mutating == Allow

-- Phase 5: command-less rules
prop_evalCommandlessArgRule :: Bool
prop_evalCommandlessArgRule =
    let Right p = parsePolicy "default allow\ndeny arg:/\\.ssh/"
    in evaluate p "cat" ["/home/user/.ssh/id_rsa"] ReadOnly == Deny
       && evaluate p "ls" ["/tmp"] ReadOnly == Allow

-- Phase 6: edge cases
prop_evalEffectUnknown :: Bool
prop_evalEffectUnknown =
    let Right p = parsePolicy "default deny\nallow effect:unknown"
    in evaluate p "totally_unknown" [] Unknown == Allow

prop_bareRuleMatchesAll :: Bool
prop_bareRuleMatchesAll =
    let Right p = parsePolicy "default allow\ndeny"
    in evaluate p "anything" ["any", "args"] Mutating == Deny

return []
runTests = $quickCheckAll
