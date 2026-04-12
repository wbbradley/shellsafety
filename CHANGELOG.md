# Changelog

All notable changes to ShellSafety will be documented in this file.

## [0.4.1] - 2026-04-12

### Fixed
- Commands with non-literal arguments (e.g. `find /path/$var -type f`) no longer
  incorrectly classified as Executing. Literal flags are now preserved for effect
  classification even when some arguments contain shell variables or expansions.

## [0.4.0] - 2026-04-08

### Breaking Changes
- Replaced `TokenComment`-based analysis output with new `SafetyResult` type
  carrying `Disposition` and message directly. Removed `makeComment`,
  `addComment`, `warn`, `info` from `ShellSafety.Analysis`; replaced with
  single `emit` function.
- Removed SC4000-SC4006 numeric diagnostic codes. Disposition (Allow/Ask/Deny)
  is now a first-class field on `SafetyResult`.
- `classifyCommand` for sh/bash/dash/ksh/zsh with `-c` now recursively parses
  and classifies the inner script rather than returning a blanket `Executing`.

### Added
- Shell `-c` classification: `sh -c 'cat file'` is now classified as ReadOnly
  instead of Executing. Supports sh, bash, dash, ksh, and zsh. Handles combined
  flags (`-exc`), `-o`/`+o` options, `--` separators, nested shells, and
  multi-command scripts.
- Recursive shell classification integrates with `find -exec sh -c ...` and
  `xargs sh -c ...` pipelines.
- `NFData` instance for `Disposition` and `SafetyResult`.

### Changed
- Parse failures now return Ask disposition with a diagnostic message instead of
  silently allowing execution.

### Fixed
- Alpine Docker builder now includes `ncurses-static` for haskeline/terminfo
  static linking.

## [0.3.5] - 2026-04-08

### Added
- Readline editing support (arrow keys, Ctrl-A/E/K) and command history in
  interactive mode via the haskeline library.
- Color-coded disposition output in interactive mode: green for allow, yellow
  for ask, red for deny.

### Changed
- Interactive mode prompt changed from `$ ` to `shellsafety> `.

## [0.3.4] - 2026-04-08

### Added
- `--version` / `-V` flag to print the current version and exit.
- Interactive REPL mode (`--interactive` / `-i`): type shell commands and see how
  the policy classifies them (allow, ask, deny) with reasons. Useful for testing
  and iterating on policy rules.

## [0.3.3] - 2026-04-07

### Changed
- Renamed default branch from `master` to `main`.

## [0.3.2] - 2026-04-07

### Added
- Recursive classification for `find -exec` clauses: `find -exec <cmd>` now
  delegates to the inner command's classifier instead of always being
  `Executing`. For example, `find -exec grep pattern {} \;` is now `ReadOnly`,
  `find -exec rm {} \;` is `Mutating`, and `find -exec curl -d data {} \;` is
  `NetworkOut`.
- Multiple `-exec` clause handling: when `find` has multiple `-exec` clauses,
  the worst (most restrictive) effect wins.
- Diagnostic messages for `find -exec` now show the inner command name (e.g.,
  `Command 'rm' (via find)`), matching the existing `xargs` behavior.

### Changed
- Log timestamps now use local time with timezone offset instead of UTC.

## [0.3.1] - 2026-04-06

### Added
- Diagnostic messages for `xargs` commands now show the inner command that drove
  the classification. For example, `xargs rm` reports `Command 'rm' (via xargs)`
  instead of `Command 'xargs'`.

### Changed
- Simplified install-from-source instructions to a single `cabal install`.

## [0.3.0] - 2026-04-06

### Added
- `--help` / `-h` flag on the `shellsafety` binary, printing setup instructions,
  usage examples, and environment variable documentation.
- Argument-aware `xargs` classification: `xargs` now parses its flags to extract
  the utility command and classify its effect. For example, `xargs grep pattern`
  is classified as ReadOnly instead of Executing. Bare `xargs` (which defaults to
  `/bin/echo`) is classified as ReadOnly.

### Changed
- Build configuration: added `cabal.project` with
  `write-ghc-environment-files: always` for easier GHCi/runghc usage.

## [0.2.0] - 2026-04-06

### Breaking Changes
- **`Disposition` type** now has three constructors: `Allow | Ask | Deny` (was
  `Allow | Deny`). Downstream code pattern-matching on `Disposition` must handle
  the new `Ask` constructor.
- **`Effect` type** now has six constructors: added `Dynamic` between
  `Executing` and `Unknown`. The `Enum` ordinal of `Unknown` shifted from 4 to
  5.
- **Hook JSON output** can now emit `"permissionDecision": "ask"`. Consumers
  that only handle `"deny"` must be updated.
- **Dynamic commands are now evaluated** instead of silently skipped. Commands
  like `$(prog)` and `` `prog` `` are now classified as `Dynamic` and subject
  to policy rules.

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
