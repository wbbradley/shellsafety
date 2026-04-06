#!/bin/bash
# Copyright 2024-2026 Will Bradley
#
# This file is part of ShellSafety.
# https://github.com/wbbradley/shellsafety
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
# ShellSafety's analysis before execution.
#
# When ShellSafety finds policy violations, the hook denies the command
# and returns the violation details so Claude can adjust.
#
# NOTE: The shellsafety binary is the preferred alternative to this
# script. It has no external dependencies (no jq required) and handles
# JSON parsing, policy file discovery, and hook output natively.
# See the installation instructions below for both options.
#
# Requirements for this script:
#   - shellsafety on PATH (or set SHELLSAFETY_BIN)
#   - jq
#   - a safety policy file at ~/.shellsafety (or set SHELLSAFETY_POLICY)
#
# Installation (Option A — shellsafety binary, recommended):
#
#   1. Build and install:
#
#        cabal build --allow-newer
#        cp "$(cabal list-bin shellsafety --allow-newer)" ~/.local/bin/
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
#                "command": "shellsafety"
#              }]
#            }]
#          }
#        }
#
# Installation (Option B — this shell script):
#
#   1. Build and install shellsafety:
#
#        cabal build --allow-newer
#        cp "$(cabal list-bin shellsafety --allow-newer)" ~/.local/bin/
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
# gate: commands that pass the policy run immediately, commands that
# violate it are denied before execution.

set -euo pipefail

SHELLCHECK="${SHELLSAFETY_BIN:-shellsafety}"
POLICY="${SHELLSAFETY_POLICY:-${SHELLCHECK_SAFETY_POLICY:-$HOME/.shellsafety}}"

if ! command -v "$SHELLCHECK" >/dev/null 2>&1; then
  echo "safety-check: shellsafety not found, skipping" >&2
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
