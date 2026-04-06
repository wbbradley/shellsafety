#!/usr/bin/env bash
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

# Interactive PreToolUse hook for Claude Code (macOS only).
#
# On deny, pops a native macOS dialog (via osascript/AppleScript) letting
# the user choose "Deny", "Allow Once", or "Add to Policy". When adding a
# rule, it validates it by re-running shellsafety and rolls back on failure.
# Keeps platform-specific UI out of the Haskell binary.
#
# Requirements:
#   - macOS (uses osascript for native dialogs)
#   - bash
#   - python3 (for JSON parsing)
#   - shellsafety binary on PATH (e.g. ~/.local/bin/shellsafety)
#
# Installation:
#   cp contrib/claude-code/interactive-hook.sh ~/.local/bin/
#   chmod +x ~/.local/bin/interactive-hook.sh
#
# Claude Code settings (~/.claude/settings.json or .claude/settings.local.json):
#
#   {
#     "permissions": { "allow": ["Bash(*)"] },
#     "hooks": {
#       "PreToolUse": [{
#         "matcher": "Bash",
#         "hooks": [{
#           "type": "command",
#           "command": "interactive-hook.sh"
#         }]
#       }]
#     }
#   }

set -euo pipefail

SAFETY_BIN="${SHELLSAFETY_BIN:-$(cd ~/src/shellsafety && cabal list-bin shellsafety --allow-newer 2>/dev/null)}"
POLICY_FILE="${SHELLSAFETY_POLICY:-${SHELLCHECK_SAFETY_POLICY:-$HOME/.shellsafety}}"

# Read hook JSON from stdin once — we may need to replay it.
input=$(cat)

# Run shellsafety, capture its stdout (deny JSON or empty).
result=$(printf '%s' "$input" | "$SAFETY_BIN" 2>/dev/null) || true

# If allowed (empty output), exit clean.
if [[ -z "$result" ]]; then
    exit 0
fi

# If ask decision, pass through to Claude Code's native prompt.
decision=$(printf '%s' "$result" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('hookSpecificOutput', {}).get('permissionDecision', 'deny'))
" 2>/dev/null) || decision="deny"

if [[ "$decision" == "ask" ]]; then
    printf '%s' "$result"
    exit 0
fi

# Extract command and reason for the dialog.
cmd=$(printf '%s' "$input" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('tool_input', {}).get('command', '(unknown)'))
" 2>/dev/null) || cmd="(could not extract command)"

reason=$(printf '%s' "$result" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d['hookSpecificOutput']['permissionDecisionReason'])
" 2>/dev/null) || reason="(denied)"

# Truncate long commands for the dialog.
display_cmd="$cmd"
if (( ${#display_cmd} > 300 )); then
    display_cmd="${display_cmd:0:300}..."
fi

show_deny_dialog() {
    local cmd_display=$1
    local reason_display=$2
    local default_rule=$3
    local add_hint=$4

    # Replace newlines with a placeholder — raw newlines break AppleScript
    # string literals.  The AppleScript helper below converts them to real
    # linefeeds for display.
    local nl_mark="%%NL%%"
    cmd_display="${cmd_display//$'\n'/$nl_mark}"
    reason_display="${reason_display//$'\n'/$nl_mark}"
    add_hint="${add_hint//$'\n'/$nl_mark}"

    osascript <<APPLESCRIPT
-- Convert %%NL%% placeholders to real linefeeds.
on decodeLF(str)
    set LF to character id 10
    set saveTID to AppleScript's text item delimiters
    set AppleScript's text item delimiters to "%%NL%%"
    set parts to text items of str
    set AppleScript's text item delimiters to LF
    set str to parts as text
    set AppleScript's text item delimiters to saveTID
    return str
end decodeLF

set cmdText to my decodeLF("Command: ${cmd_display//\"/\\\"}")
set reasonText to my decodeLF("Reason: ${reason_display//\"/\\\"}")
set dialogText to cmdText & return & return & reasonText

set chosen to choose from list {"Deny", "Ask", "Allow Once", "Add to Policy"} ¬
    with title "ShellSafety" ¬
    with prompt dialogText ¬
    default items {"Deny"}

if chosen is false then
    return ""
end if

set choice to item 1 of chosen

if choice is "Add to Policy" then
    set ruleText to text returned of (display dialog ¬
        my decodeLF("${add_hint//\"/\\\"}Append to ${POLICY_FILE//\"/\\\"}:") ¬
        with title "ShellSafety" ¬
        default answer "${default_rule//\"/\\\"}" ¬
        buttons {"Cancel", "Add"} ¬
        default button "Add")
    return "add:" & ruleText
else
    return choice
end if
APPLESCRIPT
}

# Guess a reasonable default rule from the command.
base_cmd=$(printf '%s' "$cmd" | awk '{print $1}' | xargs basename 2>/dev/null) || base_cmd=""
default_rule="allow command:${base_cmd}"
recommended="$default_rule"
add_hint=""

while true; do
    choice=$(show_deny_dialog "$display_cmd" "$reason" "$default_rule" "$add_hint") || choice=""

    case "$choice" in
        ""|"Deny")
            printf '%s' "$result"
            exit 0
            ;;
        "Ask")
            printf '%s' "$result" | python3 -c "
import sys, json
d = json.load(sys.stdin)
d['hookSpecificOutput']['permissionDecision'] = 'ask'
json.dump(d, sys.stdout)
"
            exit 0
            ;;
        "Allow Once")
            # Empty stdout = hook has no opinion = allow.
            exit 0
            ;;
        add:*)
            rule="${choice#add:}"
            # Snapshot the policy file so we can roll back on failure.
            policy_backup=$(cat "$POLICY_FILE")

            # Append the rule to the policy file.
            printf '\n%s\n' "$rule" >> "$POLICY_FILE"

            # Re-run shellsafety to validate.
            recheck=$(printf '%s' "$input" | "$SAFETY_BIN" 2>/dev/null) || true
            if [[ -z "$recheck" ]]; then
                # Rule worked — allow.
                exit 0
            fi

            # Still denied — roll back the failed rule and loop.
            printf '%s\n' "$policy_backup" > "$POLICY_FILE"
            reason=$(printf '%s' "$recheck" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d['hookSpecificOutput']['permissionDecisionReason'])
" 2>/dev/null) || reason="(still denied after rule)"
            result="$recheck"
            default_rule="$rule"
            add_hint="Recommended: ${recommended}
"
            ;;
    esac
done
