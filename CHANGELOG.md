# Changelog

All notable changes to ShellSafety will be documented in this file.

## [Unreleased]

### Added
- **`ask` disposition**: three-valued policy decisions (allow/ask/deny). `ask`
  rules pass through to Claude Code's native confirmation prompt instead of
  silently allowing or hard-blocking. Supports `default ask`, `ask [matcher...]`
  rules, and `Ask` in the disposition ordering (`Allow < Ask < Deny`).
- **`dynamic` effect category**: commands whose name is determined at runtime
  (`$(prog)`, `` `prog` ``, `$CMD`) are now classified as `dynamic` rather than
  silently skipped. Policy rules can match on `effect:dynamic`.
- **Dynamic command diagnostic codes**: SC4005 (deny) and SC4006 (ask) for
  commands with non-literal names.
- **Logging**: every invocation is logged as JSON to `~/shellsafety.log` with
  timestamp, working directory, command, decision, reasons, and raw hook input.
- **Interactive hook "Ask" option**: the macOS dialog now offers Deny, Ask,
  Allow Once, and Add to Policy. "Ask" passes through to Claude Code's native
  confirmation prompt.
- **Interactive hook newline handling**: commands and reasons containing newlines
  are now displayed correctly in macOS dialogs via AppleScript placeholder
  encoding.

### Changed
- **Hook decision output**: the binary now emits `"permissionDecision": "ask"`
  JSON for ask-disposition commands (previously only `"deny"` or empty).
- **Interactive hook dialog**: switched from `display dialog` with buttons to
  `choose from list` for cleaner multi-option selection.

## [0.1.0] - 2026-04-05

Initial release. Forked from [ShellCheck](https://www.shellcheck.net/) by Vidar
Holen.

### Added
- Shell command parser (inherited from ShellCheck) supporting bash, sh, dash,
  ksh, and busybox sh.
- Effect classification database (~150 commands) across five categories:
  `readonly`, `mutating`, `network_out`, `executing`, `unknown`.
- Argument-sensitive classification for `git`, `curl`, and `find`.
- Output redirection detection: commands with `>`, `>>`, `>|` to real files are
  upgraded to at least `mutating`. Redirections to `/dev/null` are excluded.
- Policy DSL with `assume`, `default`, `allow`/`deny` rules, and matchers:
  `command:<name>`, `effect:<category>`, `arg:<literal>`, `arg:/<regex>/`.
  Last-matching-rule-wins semantics.
- Claude Code `PreToolUse` hook binary reading JSON from stdin.
- Environment variable support: `SHELLSAFETY_POLICY` (primary),
  `SHELLCHECK_SAFETY_POLICY` (fallback), default `~/.shellsafety`.
- Interactive macOS hook script (`contrib/claude-code/interactive-hook.sh`) with
  native dialogs for deny override and on-the-fly policy editing.
- Prebuilt binaries for linux.x86_64, linux.aarch64, darwin.x86_64,
  darwin.aarch64 via GitHub Actions.
- Diagnostic codes SC4000 (allow), SC4001 (known deny), SC4002 (unknown deny).
