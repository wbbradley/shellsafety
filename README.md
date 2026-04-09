# ShellSafety

ShellSafety is a safety gate for AI agent shell command execution. It parses
shell commands, classifies their effects (read-only, mutating, network,
executing, dynamic), and evaluates them against a configurable policy to allow,
prompt for confirmation, or deny execution. It is designed to be used as a
[Claude Code](https://docs.anthropic.com/en/docs/claude-code) `PreToolUse` hook
so that AI agents can run permitted commands without human confirmation while
dangerous or unknown commands are blocked or flagged before execution.

Derived from [ShellCheck](https://www.shellcheck.net/) by Vidar Holen, licensed
under [GPL-3](LICENSE).

## Install

### From GitHub releases (recommended)

Download a prebuilt binary for your platform:

```sh
# macOS (Apple Silicon)
curl -L https://github.com/wbbradley/shellsafety/releases/download/latest/shellsafety-latest.darwin.aarch64.tar.xz | tar xJ
cp shellsafety-latest/shellsafety ~/.local/bin/

# macOS (Intel)
curl -L https://github.com/wbbradley/shellsafety/releases/download/latest/shellsafety-latest.darwin.x86_64.tar.xz | tar xJ
cp shellsafety-latest/shellsafety ~/.local/bin/

# Linux (x86_64)
curl -L https://github.com/wbbradley/shellsafety/releases/download/latest/shellsafety-latest.linux.x86_64.tar.xz | tar xJ
cp shellsafety-latest/shellsafety ~/.local/bin/

# Linux (aarch64)
curl -L https://github.com/wbbradley/shellsafety/releases/download/latest/shellsafety-latest.linux.aarch64.tar.xz | tar xJ
cp shellsafety-latest/shellsafety ~/.local/bin/
```

### From source

```sh
cabal install
```

## Quick Start

### Create a policy

Write a policy file at `~/.shellsafety`:

```
assume bash
default deny
allow effect:readonly
allow command:git
deny command:git arg:push
```

### Configure Claude Code

Add to `~/.claude/settings.json` (or `.claude/settings.local.json` per-project):

```json
{
  "permissions": { "allow": ["Bash(*)"] },
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [{
        "type": "command",
        "command": "shellsafety"
      }]
    }]
  }
}
```

With `"allow": ["Bash(*)"]`, all Bash commands pass through the permission system
without prompting. The hook acts as the sole safety gate: commands that pass the
policy run immediately; commands that violate it are denied before execution.

### Try it out

Test commands interactively against your policy:

```sh
shellsafety -i
shellsafety> ls -la
disposition: allow
reasons:
  Command 'ls' classified as ReadOnly, allowed by safety policy (allow effect:readonly)
shellsafety> rm -rf /
disposition: deny
reasons:
  Command 'rm' classified as Mutating, denied by safety policy
```

Interactive mode supports readline editing (arrow keys, Ctrl-A/E/K) and command
history via haskeline. Disposition output is color-coded: green for allow, yellow
for ask, red for deny.

### Interactive mode (macOS)

For an interactive experience where denied commands pop up a native dialog
letting you allow once or add a policy rule on the fly, see
[`contrib/claude-code/interactive-hook.sh`](contrib/claude-code/interactive-hook.sh).

## Policy DSL Reference

A policy file is a sequence of directives, one per line. Blank lines and lines
starting with `#` are ignored.

### `assume <shell>`

Sets the shell dialect for parsing (e.g., `assume bash`). If omitted, the
shebang or default is used.

### `default allow` / `default ask` / `default deny`

Sets the fallback disposition when no rule matches. Default is `deny`.

### `allow [matcher...]` / `ask [matcher...]` / `deny [matcher...]`

Rules are evaluated top-to-bottom; the **last matching rule wins**. Each rule can
have zero or more matchers. All matchers on a rule must match for the rule to
apply (AND logic). A rule with no matchers matches everything.

The three dispositions are:

- **allow** — command runs immediately, no confirmation
- **ask** — passed to Claude Code's native confirmation prompt
- **deny** — command is blocked before execution

### Matchers

| Matcher | Description |
|---------|-------------|
| `command:<name>` | Matches when the command basename equals `<name>` |
| `effect:<category>` | Matches when the command's classified effect equals `<category>` |
| `arg:<literal>` | Matches when any argument exactly equals `<literal>` |
| `arg:/<regex>/` | Matches when any argument matches the regex |

## Effect Categories

ShellSafety classifies every command into one of six effect categories. In
pipelines, the most conservative (highest) effect wins.

| Effect | Description | Examples |
|--------|-------------|----------|
| `readonly` | Only reads data, no side effects | `cat`, `ls`, `grep`, `wc`, `git status` |
| `mutating` | Modifies files or system state | `rm`, `mv`, `chmod`, `git commit`, `apt install` |
| `network_out` | Sends data over the network | `curl -d`, `ssh`, `wget`, `git push` |
| `executing` | Runs arbitrary commands | `sudo`, `python`, `eval`, `perl` |
| `dynamic` | Command name determined at runtime | `$(prog)`, `` `prog` ``, `$CMD` |
| `unknown` | Command not in the built-in database | Any unrecognized command |

Some commands are classified context-sensitively based on their arguments:

- **git**: `git status` is ReadOnly, `git push` is NetworkOut, `git commit` is Mutating
- **curl**: `curl <url>` (GET) is ReadOnly, `curl -d data <url>` is NetworkOut
- **find**: `find . -name '*.log'` is ReadOnly, `find -exec grep pattern` is ReadOnly (classified by the inner command), `find -exec rm` is Mutating, `find -delete` is Mutating
- **xargs**: `xargs grep pattern` is ReadOnly (classified by the utility command), bare `xargs` is ReadOnly (defaults to `/bin/echo`)
- **sh/bash/dash/ksh/zsh**: `sh -c 'cat file'` is ReadOnly (classified by the inner script), `bash -c 'rm file'` is Mutating, bare `sh` or `sh script.sh` is Executing

### Output Redirection

When a command has output redirection (`>`, `>>`, `>|`) to a real file, its
effect is upgraded to at least `mutating`. For example, `echo hello > file.txt`
is classified as Mutating even though `echo` alone is ReadOnly. Redirections to
`/dev/null` are excluded from this upgrade.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SHELLSAFETY_POLICY` | Path to the policy file (overrides default `~/.shellsafety`) |
| `SHELLCHECK_SAFETY_POLICY` | Fallback if `SHELLSAFETY_POLICY` is not set |
| `SHELLSAFETY_BIN` | Path to the `shellsafety` binary (used by `interactive-hook.sh`) |

## Logging

Every invocation is logged as a JSON line to `~/shellsafety.log` with
timestamp, working directory, command, decision (`allow`/`ask`/`deny`/`skip`),
and reasons.

## Example Policy

```
# Parse commands as bash
assume bash

# Block everything by default
default deny

# Allow all read-only commands
allow effect:readonly

# Prompt for unknown commands instead of blocking
ask effect:unknown

# Allow git, but not push
allow command:git
deny command:git arg:push

# Allow make
allow command:make

# Block anything touching .ssh
deny arg:/.ssh/
```

## Attribution

ShellSafety is derived from [ShellCheck](https://www.shellcheck.net/) by
[Vidar Holen](https://github.com/koalaman/). Licensed under the
[GNU General Public License v3.0](LICENSE).
