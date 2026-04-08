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
module ShellSafety.Effects (
    Effect(..),
    EffectDB,
    builtinEffects,
    classifyCommand
    , runTests  -- STRIP
    ) where

import Data.List (isPrefixOf, maximumBy)
import Data.Ord (comparing)
import qualified Data.Map.Strict as M
import Test.QuickCheck

-- | Effect classification for shell commands.
-- Constructor order matters: ReadOnly < Mutating < NetworkOut < Executing < Dynamic < Unknown
-- so that 'maximum' over a pipeline yields the most conservative effect.
data Effect = ReadOnly | Mutating | NetworkOut | Executing | Dynamic | Unknown
    deriving (Eq, Ord, Show, Enum, Bounded)

instance Arbitrary Effect where  -- STRIP
    arbitrary = arbitraryBoundedEnum  -- STRIP

-- | Database mapping command basenames to their default effect.
type EffectDB = M.Map String Effect

-- Command lists by effect category

readOnlyCommands :: [(String, Effect)]
readOnlyCommands = map (\c -> (c, ReadOnly))
    [ "base32", "base64", "basename", "cal", "cat", "cksum", "cmp"
    , "column", "comm", "csplit", "cut", "date", "df", "diff", "dir"
    , "dircolors", "dirname", "du", "echo", "expand", "expr"
    , "factor", "false", "file", "fmt", "fold", "getconf", "getopt"
    , "groups", "head", "hostid", "hostname", "id", "join", "last"
    , "less", "locale", "logname", "look", "ls", "lsblk", "lsof"
    , "md5sum", "more", "namei", "nl", "nproc", "numfmt", "od"
    , "paste", "pathchk", "printenv", "printf", "ps", "pwd", "readlink"
    , "realpath", "rev", "seq", "sha1sum", "sha256sum", "sha512sum"
    , "stat", "strings", "stty", "sum", "tabs", "tac", "tail", "test"
    , "tr", "true", "tsort", "tty", "type", "uname", "unexpand"
    , "uniq", "uptime", "users", "vdir", "wc", "which", "who"
    , "whoami", "yes"
    -- Non-POSIX read-only tools agents commonly use
    , "bat", "exa", "eza", "fd", "fzf", "hexdump", "jq", "pgrep"
    , "rg", "tree", "xxd", "yq"
    -- VCS read-only
    , "git-log", "git-status", "git-diff", "git-show", "git-branch"
    -- grep family
    , "grep", "egrep", "fgrep"
    ]

mutatingCommands :: [(String, Effect)]
mutatingCommands = map (\c -> (c, Mutating))
    [ "chgrp", "chmod", "chown", "cp", "dd", "fallocate", "install"
    , "ln", "mkdir", "mkfifo", "mknod", "mktemp", "mv", "patch"
    , "rm", "rmdir", "shred", "split", "sync", "touch", "truncate"
    -- Editors / in-place tools (conservative: sed -i, sort -o possible)
    , "sed", "sort", "tee"
    -- Process/user/system mutation
    , "chroot", "kill", "killall", "mount", "nice", "nohup", "pkill"
    , "renice", "umount", "useradd", "userdel", "usermod"
    -- Package managers (mutate system state)
    , "apt", "apt-get", "brew", "dnf", "dpkg", "npm", "pip", "pip3"
    , "rpm", "yum"
    -- Archive/compression (create/extract files)
    , "ar", "bzip2", "compress", "cpio", "gzip", "lz4", "lzma"
    , "tar", "unzip", "xz", "zip", "zstd"
    -- Git mutating
    , "git"
    ]

networkOutCommands :: [(String, Effect)]
networkOutCommands = map (\c -> (c, NetworkOut))
    [ "curl", "dig", "ftp", "host", "nc", "netcat", "nslookup"
    , "ping", "rsync", "scp", "sftp", "ssh", "telnet", "traceroute"
    , "wget"
    ]

executingCommands :: [(String, Effect)]
executingCommands = map (\c -> (c, Executing))
    [ "bash", "csh", "dash", "env", "eval", "exec", "expect", "fish"
    , "ksh", "make", "nawk", "perl", "php", "python", "python3"
    , "ruby", "sh", "sudo", "su", "tcsh", "zsh"
    -- find is handled by classifyFind
    -- Docker runs arbitrary commands
    , "docker", "podman"
    -- xargs is handled by classifyXargs but kept here as a fallback
    -- for the builtinEffects map (conservative default)
    , "xargs"
    ]

allPairs :: [(String, Effect)]
allPairs = readOnlyCommands ++ mutatingCommands ++ networkOutCommands ++ executingCommands

-- | Built-in effect database. Later entries win on duplicates (e.g. env
-- appears in both ReadOnly and Executing; Executing wins).
builtinEffects :: EffectDB
builtinEffects = M.fromList allPairs

-- | Classify a command by its basename and arguments.
-- Returns (effectiveCommandName, effect) so callers can report which command
-- actually drove the classification (e.g. "rm" via xargs).
classifyCommand :: String -> [String] -> (String, Effect)
classifyCommand "git"   args = ("git",  classifyGit args)
classifyCommand "curl"  args = ("curl", classifyCurl args)
classifyCommand "find"  args = classifyFind args
classifyCommand "xargs" args = classifyXargs args
classifyCommand cmd     _    = (cmd,    M.findWithDefault Unknown cmd builtinEffects)

classifyGit :: [String] -> Effect
classifyGit [] = Mutating
classifyGit (sub:_)
    | sub `elem` gitReadOnlySubs = ReadOnly
    | sub `elem` gitNetworkSubs  = NetworkOut
    | otherwise                  = Mutating

gitReadOnlySubs :: [String]
gitReadOnlySubs =
    [ "log", "status", "diff", "show", "branch", "tag", "describe"
    , "shortlog", "rev-parse", "rev-list", "ls-files", "ls-tree"
    , "cat-file", "name-rev", "blame", "grep"
    ]

gitNetworkSubs :: [String]
gitNetworkSubs = ["push", "fetch", "pull", "clone"]

classifyCurl :: [String] -> Effect
classifyCurl [] = NetworkOut
classifyCurl args
    | any isUpload args = NetworkOut
    | otherwise = ReadOnly
  where
    isUpload a = a `elem` shortFlags || any (`isPrefixOf` a) longFlagPrefixes
    shortFlags = ["-d", "-F", "-T", "-X"]
    longFlagPrefixes =
        [ "--data", "--data-raw", "--data-binary", "--data-urlencode"
        , "--form", "--form-string"
        , "--upload-file"
        , "--request"
        ]

classifyFind :: [String] -> (String, Effect)
classifyFind [] = ("find", Executing)
classifyFind args =
    let execClauses = extractExecClauses args
        hasDelete = "-delete" `elem` args
        deleteEffect = if hasDelete then [("find", Mutating)] else []
        execEffects = map classifyExecClause execClauses ++ deleteEffect
    in case execEffects of
        [] -> ("find", ReadOnly)
        es -> maximumBy (comparing snd) es

extractExecClauses :: [String] -> [[String]]
extractExecClauses [] = []
extractExecClauses (x:xs)
    | x `elem` ["-exec", "-execdir", "-ok", "-okdir"] =
        let (clause, rest) = span (\a -> a /= ";" && a /= "+") xs
        in clause : extractExecClauses (drop 1 rest)
    | otherwise = extractExecClauses xs

classifyExecClause :: [String] -> (String, Effect)
classifyExecClause [] = ("find", Executing)
classifyExecClause (cmd:rest) = classifyCommand cmd rest

classifyXargs :: [String] -> (String, Effect)
classifyXargs args = case stripXargsOpts args of
    []         -> ("echo", ReadOnly)  -- no utility: xargs defaults to /bin/echo
    (cmd:rest) -> classifyCommand cmd rest

-- | Strip xargs options, returning the utility name and its arguments.
stripXargsOpts :: [String] -> [String]
stripXargsOpts [] = []
stripXargsOpts ("--":rest) = rest
stripXargsOpts (arg:rest)
    | "--" `isPrefixOf` arg = stripXargsLong arg rest
    | "-" `isPrefixOf` arg, length arg > 1 = stripXargsShort (drop 1 arg) rest
    | otherwise = arg : rest

stripXargsLong :: String -> [String] -> [String]
stripXargsLong opt rest
    | '=' `elem` opt = stripXargsOpts rest  -- value embedded: --max-args=5
    | name `elem` ["--null", "--no-run-if-empty", "--verbose", "--replace"]
        = stripXargsOpts rest
    | name `elem` ["--max-args", "--max-procs", "--delimiter"]
        = stripXargsOpts (drop 1 rest)
    | otherwise = stripXargsOpts rest  -- unknown long opt, skip
  where name = takeWhile (/= '=') opt

stripXargsShort :: String -> [String] -> [String]
stripXargsShort [] rest = stripXargsOpts rest
stripXargsShort (c:cs) rest
    | c `elem` "0oprtx" = stripXargsShort cs rest
    | c `elem` "EIJLPRSdns" =
        if null cs
        then stripXargsOpts (drop 1 rest)
        else stripXargsOpts rest
    | otherwise = stripXargsShort cs rest

-- Tests

prop_classifyReadOnly :: Bool
prop_classifyReadOnly = snd (classifyCommand "cat" []) == ReadOnly

prop_classifyMutating :: Bool
prop_classifyMutating = snd (classifyCommand "rm" []) == Mutating

prop_classifyNetworkOut :: Bool
prop_classifyNetworkOut = snd (classifyCommand "curl" []) == NetworkOut

prop_classifyExecuting :: Bool
prop_classifyExecuting = snd (classifyCommand "sudo" []) == Executing

prop_classifyUnknown :: Bool
prop_classifyUnknown = snd (classifyCommand "totally_unknown_cmd_xyz" []) == Unknown

prop_classifyIgnoresArgsForSimpleCommands :: Bool
prop_classifyIgnoresArgsForSimpleCommands =
    snd (classifyCommand "cat" ["file1", "file2"]) == snd (classifyCommand "cat" [])

prop_effectOrdering :: Bool
prop_effectOrdering =
    ReadOnly < Mutating
    && Mutating < NetworkOut
    && NetworkOut < Executing
    && Executing < Dynamic
    && Dynamic < Unknown

prop_builtinEffectsNonEmpty :: Bool
prop_builtinEffectsNonEmpty = not (M.null builtinEffects)

prop_builtinEffectsNoUnknown :: Bool
prop_builtinEffectsNoUnknown = all (/= Unknown) (M.elems builtinEffects)

prop_noDuplicateKeys :: Bool
prop_noDuplicateKeys = M.size builtinEffects == length allPairs

-- Effective command name tests
prop_effectiveNameSimple = fst (classifyCommand "cat" []) == "cat"
prop_effectiveNameXargsRm = fst (classifyCommand "xargs" ["rm"]) == "rm"
prop_effectiveNameXargsGrep = fst (classifyCommand "xargs" ["grep", "foo"]) == "grep"
prop_effectiveNameXargsBare = fst (classifyCommand "xargs" []) == "echo"
prop_effectiveNameXargsFlagsRm = fst (classifyCommand "xargs" ["-0", "-I", "{}", "rm", "{}"]) == "rm"
prop_effectiveNameGit = fst (classifyCommand "git" ["status"]) == "git"
prop_effectiveNameXargsCurl = fst (classifyCommand "xargs" ["curl", "-d", "data"]) == "curl"
prop_effectiveNameXargsUnknown = fst (classifyCommand "xargs" ["my-cmd"]) == "my-cmd"

-- Git argument-aware classification
prop_gitStatusReadOnly = snd (classifyCommand "git" ["status"]) == ReadOnly
prop_gitLogReadOnly = snd (classifyCommand "git" ["log", "--oneline"]) == ReadOnly
prop_gitDiffReadOnly = snd (classifyCommand "git" ["diff"]) == ReadOnly
prop_gitPushNetworkOut = snd (classifyCommand "git" ["push", "origin", "main"]) == NetworkOut
prop_gitFetchNetworkOut = snd (classifyCommand "git" ["fetch"]) == NetworkOut
prop_gitCloneNetworkOut = snd (classifyCommand "git" ["clone", "url"]) == NetworkOut
prop_gitCommitMutating = snd (classifyCommand "git" ["commit", "-m", "msg"]) == Mutating
prop_gitAddMutating = snd (classifyCommand "git" ["add", "."]) == Mutating
prop_gitNoSubMutating = snd (classifyCommand "git" []) == Mutating

-- Curl argument-aware classification
prop_curlDefaultGetReadOnly = snd (classifyCommand "curl" ["http://example.com"]) == ReadOnly
prop_curlPostNetworkOut = snd (classifyCommand "curl" ["-d", "data", "http://example.com"]) == NetworkOut
prop_curlUploadNetworkOut = snd (classifyCommand "curl" ["-T", "file", "http://example.com"]) == NetworkOut
prop_curlNoArgsNetworkOut = snd (classifyCommand "curl" []) == NetworkOut
prop_curlFormNetworkOut = snd (classifyCommand "curl" ["-F", "file=@f", "http://example.com"]) == NetworkOut

-- Find argument-aware classification
prop_findSimpleReadOnly = snd (classifyCommand "find" [".", "-name", "*.log"]) == ReadOnly
prop_findDeleteMutating = snd (classifyCommand "find" [".", "-name", "*.tmp", "-delete"]) == Mutating
prop_findExecRmMutating = snd (classifyCommand "find" [".", "-exec", "rm", "{}", ";"]) == Mutating
prop_findNoArgsExecuting = snd (classifyCommand "find" []) == Executing

-- Find effective name tests
prop_findExecRmName = fst (classifyCommand "find" [".", "-exec", "rm", "{}", ";"]) == "rm"
prop_findSimpleName = fst (classifyCommand "find" [".", "-name", "*.log"]) == "find"
prop_findExecGrepName = fst (classifyCommand "find" [".", "-exec", "grep", "pattern", "{}", ";"]) == "grep"

-- Find recursive classification
prop_findExecGrepReadOnly = snd (classifyCommand "find" [".", "-exec", "grep", "pattern", "{}", ";"]) == ReadOnly
prop_findExecCurlNetworkOut = snd (classifyCommand "find" [".", "-exec", "curl", "-d", "data", "{}", ";"]) == NetworkOut
prop_findExecShExecuting = snd (classifyCommand "find" [".", "-exec", "sh", "-c", "echo {}", ";"]) == Executing

-- Find multiple exec clauses: worst effect wins
prop_findMultiExec = snd (classifyCommand "find" [".", "-exec", "cat", "{}", ";", "-exec", "rm", "{}", ";"]) == Mutating

-- Find -exec + -delete coexistence
prop_findExecChmodDelete = snd (classifyCommand "find" [".", "-exec", "chmod", "644", "{}", ";", "-delete"]) == Mutating

-- Find unknown inner command
prop_findExecUnknown = snd (classifyCommand "find" [".", "-exec", "my-cmd", "{}", ";"]) == Unknown

-- Tee
prop_teeMutating = snd (classifyCommand "tee" ["output.log"]) == Mutating

-- Curl --flag=value syntax
prop_curlDataEqualsNetworkOut = snd (classifyCommand "curl" ["--data=hello", "http://example.com"]) == NetworkOut
prop_curlFormEqualsNetworkOut = snd (classifyCommand "curl" ["--form=file=@f", "http://example.com"]) == NetworkOut
prop_curlUploadFileEqualsNetworkOut = snd (classifyCommand "curl" ["--upload-file=f", "http://example.com"]) == NetworkOut
prop_curlRequestEqualsNetworkOut = snd (classifyCommand "curl" ["--request=POST", "http://example.com"]) == NetworkOut

-- Xargs argument-aware classification
prop_xargsNoUtilReadOnly = snd (classifyCommand "xargs" []) == ReadOnly
prop_xargsRmMutating = snd (classifyCommand "xargs" ["rm"]) == Mutating
prop_xargsFlag0Rm = snd (classifyCommand "xargs" ["-0", "rm"]) == Mutating
prop_xargsReplaceRm = snd (classifyCommand "xargs" ["-I", "{}", "rm", "{}"]) == Mutating
prop_xargsGrepReadOnly = snd (classifyCommand "xargs" ["grep", "pattern"]) == ReadOnly
prop_xargsManyFlagsCurl = snd (classifyCommand "xargs" ["-n", "1", "-P", "4", "curl", "https://example.com"]) == ReadOnly
prop_xargsComplexUnknown = snd (classifyCommand "xargs" ["-I", "XX", "-R", "foo", "-S", "23", "-n", "3", "my-cmd", "--option-a", "XX"]) == Unknown
prop_xargsCurlPostNetworkOut = snd (classifyCommand "xargs" ["curl", "-d", "data", "url"]) == NetworkOut
prop_xargsDashDashRm = snd (classifyCommand "xargs" ["--", "rm", "-f"]) == Mutating
prop_xargsCombinedFlags = snd (classifyCommand "xargs" ["-0pt", "rm"]) == Mutating
prop_xargsGnuLongNull = snd (classifyCommand "xargs" ["--null", "rm"]) == Mutating
prop_xargsGnuMaxArgs = snd (classifyCommand "xargs" ["--max-args=5", "rm"]) == Mutating
prop_xargsGnuMaxArgsSpace = snd (classifyCommand "xargs" ["--max-args", "5", "rm"]) == Mutating
prop_xargsGnuReplace = snd (classifyCommand "xargs" ["--replace", "rm", "{}"]) == Mutating
prop_xargsGnuVerbose = snd (classifyCommand "xargs" ["--verbose", "cat", "file"]) == ReadOnly

return []
runTests = $quickCheckAll
