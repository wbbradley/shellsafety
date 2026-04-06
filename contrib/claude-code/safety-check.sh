#!/bin/bash
# Copyright 2024-2026 Will Bradley
#
# This file is part of ShellSafety.
# https://github.com/wbbradley/shellcheck
#
# ShellSafety is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ShellSafety is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# PreToolUse hook for Claude Code: runs proposed Bash commands through
# shellcheck's safety analysis before execution.
#
# When shellcheck finds safety policy violations, the hook denies the
# command and returns the violation details so Claude can adjust.
#
# NOTE: The shellcheck-safety binary is the preferred alternative to
# this script. It has no external dependencies (no jq required) and
# handles JSON parsing, policy file discovery, and hook output natively.
# See the installation instructions below for both options.
#
# Requirements for this script:
#   - shellcheck (with safety policy support) on PATH
#   - jq
#   - a safety policy file at ~/.shellsafety (or set SHELLCHECK_SAFETY_POLICY)
#
# Installation (Option A — shellcheck-safety binary, recommended):
#
#   1. Build and install:
#
#        cabal build --allow-newer
#        cp "$(cabal list-bin shellcheck-safety --allow-newer)" ~/.local/bin/
#
#   2. Create a safety policy at ~/.shellsafety:
#
#        assume bash
#        default deny
#        allow effect:readonly
#
#   3. Add the hook to your Claude Code settings. Either globally
#      (~/.claude/settings.json) or per-project (.claude/settings.local.json):
#
#        {
#          "permissions": { "allow": ["Bash(*)"] },
#          "hooks": {
#            "PreToolUse": [{
#              "matcher": "Bash",
#              "hooks": [{
#                "type": "command",
#                "command": "shellcheck-safety"
#              }]
#            }]
#          }
#        }
#
# Installation (Option B — this shell script):
#
#   1. Build and install shellcheck:
#
#        cabal build --allow-newer
#        cp "$(cabal list-bin shellcheck --allow-newer)" ~/.local/bin/
#
#   2. Create a safety policy at ~/.shellsafety (same as above).
#
#   3. Copy this script and configure the hook:
#
#        mkdir -p ~/.claude/hooks
#        cp contrib/claude-code/safety-check.sh ~/.claude/hooks/
#        chmod +x ~/.claude/hooks/safety-check.sh
#
#      Then add to your Claude Code settings:
#
#        {
#          "permissions": { "allow": ["Bash(*)"] },
#          "hooks": {
#            "PreToolUse": [{
#              "matcher": "Bash",
#              "hooks": [{
#                "type": "command",
#                "command": "~/.claude/hooks/safety-check.sh"
#              }]
#            }]
#          }
#        }
#
# In both cases, "allow": ["Bash(*)"] lets all Bash commands through the
# permission system without prompting. The hook acts as the sole safety
# gate: commands that pass shellcheck run immediately, commands that
# violate the policy are denied before execution.

set -euo pipefail

SHELLCHECK="${SHELLCHECK_PATH:-shellcheck}"
POLICY="${SHELLCHECK_SAFETY_POLICY:-$HOME/.shellsafety}"

if ! command -v "$SHELLCHECK" >/dev/null 2>&1; then
  echo "safety-check: shellcheck not found, skipping" >&2
  exit 0
fi

if [ ! -f "$POLICY" ]; then
  echo "safety-check: no policy file at $POLICY, skipping" >&2
  exit 0
fi

COMMAND=$(jq -r '.tool_input.command')

OUTPUT=$(printf '#!/bin/bash\n%s\n' "$COMMAND" | "$SHELLCHECK" --safety-policy "$POLICY" --enable=safety - 2>&1) && exit 0

jq -n --arg reason "$OUTPUT" '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "deny",
    permissionDecisionReason: $reason
  }
}'
