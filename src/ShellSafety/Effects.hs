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

import Data.List (isPrefixOf)
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
    , "ruby", "sh", "sudo", "su", "tcsh", "xargs", "zsh"
    -- find is Executing because of -exec
    , "find"
    -- Docker runs arbitrary commands
    , "docker", "podman"
    ]

allPairs :: [(String, Effect)]
allPairs = readOnlyCommands ++ mutatingCommands ++ networkOutCommands ++ executingCommands

-- | Built-in effect database. Later entries win on duplicates (e.g. env
-- appears in both ReadOnly and Executing; Executing wins).
builtinEffects :: EffectDB
builtinEffects = M.fromList allPairs

-- | Classify a command by its basename and arguments.
classifyCommand :: String -> [String] -> Effect
classifyCommand "git"  args = classifyGit args
classifyCommand "curl" args = classifyCurl args
classifyCommand "find" args = classifyFind args
classifyCommand cmd    _    = M.findWithDefault Unknown cmd builtinEffects

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

classifyFind :: [String] -> Effect
classifyFind [] = Executing
classifyFind args
    | hasExec   = Executing
    | hasDelete = Mutating
    | otherwise = ReadOnly
  where
    hasExec   = any (`elem` ["-exec", "-execdir", "-ok", "-okdir"]) args
    hasDelete = "-delete" `elem` args

-- Tests

prop_classifyReadOnly :: Bool
prop_classifyReadOnly = classifyCommand "cat" [] == ReadOnly

prop_classifyMutating :: Bool
prop_classifyMutating = classifyCommand "rm" [] == Mutating

prop_classifyNetworkOut :: Bool
prop_classifyNetworkOut = classifyCommand "curl" [] == NetworkOut

prop_classifyExecuting :: Bool
prop_classifyExecuting = classifyCommand "sudo" [] == Executing

prop_classifyUnknown :: Bool
prop_classifyUnknown = classifyCommand "totally_unknown_cmd_xyz" [] == Unknown

prop_classifyIgnoresArgsForSimpleCommands :: Bool
prop_classifyIgnoresArgsForSimpleCommands =
    classifyCommand "cat" ["file1", "file2"] == classifyCommand "cat" []

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

-- Git argument-aware classification
prop_gitStatusReadOnly = classifyCommand "git" ["status"] == ReadOnly
prop_gitLogReadOnly = classifyCommand "git" ["log", "--oneline"] == ReadOnly
prop_gitDiffReadOnly = classifyCommand "git" ["diff"] == ReadOnly
prop_gitPushNetworkOut = classifyCommand "git" ["push", "origin", "main"] == NetworkOut
prop_gitFetchNetworkOut = classifyCommand "git" ["fetch"] == NetworkOut
prop_gitCloneNetworkOut = classifyCommand "git" ["clone", "url"] == NetworkOut
prop_gitCommitMutating = classifyCommand "git" ["commit", "-m", "msg"] == Mutating
prop_gitAddMutating = classifyCommand "git" ["add", "."] == Mutating
prop_gitNoSubMutating = classifyCommand "git" [] == Mutating

-- Curl argument-aware classification
prop_curlDefaultGetReadOnly = classifyCommand "curl" ["http://example.com"] == ReadOnly
prop_curlPostNetworkOut = classifyCommand "curl" ["-d", "data", "http://example.com"] == NetworkOut
prop_curlUploadNetworkOut = classifyCommand "curl" ["-T", "file", "http://example.com"] == NetworkOut
prop_curlNoArgsNetworkOut = classifyCommand "curl" [] == NetworkOut
prop_curlFormNetworkOut = classifyCommand "curl" ["-F", "file=@f", "http://example.com"] == NetworkOut

-- Find argument-aware classification
prop_findSimpleReadOnly = classifyCommand "find" [".", "-name", "*.log"] == ReadOnly
prop_findDeleteMutating = classifyCommand "find" [".", "-name", "*.tmp", "-delete"] == Mutating
prop_findExecExecuting = classifyCommand "find" [".", "-exec", "rm", "{}", ";"] == Executing
prop_findNoArgsExecuting = classifyCommand "find" [] == Executing

-- Tee
prop_teeMutating = classifyCommand "tee" ["output.log"] == Mutating

-- Curl --flag=value syntax
prop_curlDataEqualsNetworkOut = classifyCommand "curl" ["--data=hello", "http://example.com"] == NetworkOut
prop_curlFormEqualsNetworkOut = classifyCommand "curl" ["--form=file=@f", "http://example.com"] == NetworkOut
prop_curlUploadFileEqualsNetworkOut = classifyCommand "curl" ["--upload-file=f", "http://example.com"] == NetworkOut
prop_curlRequestEqualsNetworkOut = classifyCommand "curl" ["--request=POST", "http://example.com"] == NetworkOut

return []
runTests = $quickCheckAll
