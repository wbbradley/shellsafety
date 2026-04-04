#!/bin/bash
# PreToolUse hook for Claude Code: runs proposed Bash commands through
# shellcheck's safety analysis before execution.
#
# When shellcheck finds safety policy violations, the hook denies the
# command and returns the violation details so Claude can adjust.
#
# Requirements:
#   - shellcheck (with safety policy support) on PATH
#   - jq
#   - a safety policy file at ~/.shellsafety (or set SHELLCHECK_SAFETY_POLICY)
#
# Installation:
#
#   1. Build and install shellcheck (with safety support):
#
#        cabal build --allow-newer
#        cp "$(cabal list-bin shellcheck --allow-newer)" ~/.local/bin/
#
#   2. Create a safety policy at ~/.shellsafety:
#
#        assume bash
#        default deny
#        allow effect:readonly
#
#      See the shellcheck safety documentation for the full policy DSL.
#
#   3. Copy this script somewhere persistent and make it executable:
#
#        mkdir -p ~/.claude/hooks
#        cp contrib/claude-code/safety-check.sh ~/.claude/hooks/
#        chmod +x ~/.claude/hooks/safety-check.sh
#
#   4. Add the hook to your Claude Code settings. Either globally
#      (~/.claude/settings.json) or per-project (.claude/settings.local.json):
#
#        {
#          "permissions": {
#            "allow": ["Bash(*)"]
#          },
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
#      "allow": ["Bash(*)"] lets all Bash commands through the permission
#      system without prompting. The hook then acts as the sole safety gate:
#      commands that pass shellcheck run immediately, commands that violate
#      the policy are denied before execution.

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
