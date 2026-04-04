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
module ShellCheck.Safety.Effects (
    Effect(..),
    EffectDB,
    builtinEffects,
    classifyCommand,
    runTests
    ) where

import qualified Data.Map.Strict as M
import Test.QuickCheck

-- | Effect classification for shell commands.
-- Constructor order matters: ReadOnly < Mutating < NetworkOut < Executing < Unknown
-- so that 'maximum' over a pipeline yields the most conservative effect.
data Effect = ReadOnly | Mutating | NetworkOut | Executing | Unknown
    deriving (Eq, Ord, Show, Enum, Bounded)

instance Arbitrary Effect where
    arbitrary = arbitraryBoundedEnum

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
    , "sed", "sort"
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

-- | Classify a command by its basename. Arguments are ignored in Phase 1.
classifyCommand :: String -> [String] -> Effect
classifyCommand cmd _args = M.findWithDefault Unknown cmd builtinEffects

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

prop_classifyIgnoresArgs :: Bool
prop_classifyIgnoresArgs =
    classifyCommand "cat" ["file1", "file2"] == classifyCommand "cat" []

prop_effectOrdering :: Bool
prop_effectOrdering =
    ReadOnly < Mutating
    && Mutating < NetworkOut
    && NetworkOut < Executing
    && Executing < Unknown

prop_builtinEffectsNonEmpty :: Bool
prop_builtinEffectsNonEmpty = not (M.null builtinEffects)

prop_builtinEffectsNoUnknown :: Bool
prop_builtinEffectsNoUnknown = all (/= Unknown) (M.elems builtinEffects)

prop_noDuplicateKeys :: Bool
prop_noDuplicateKeys = M.size builtinEffects == length allPairs

return []
runTests = $quickCheckAll
