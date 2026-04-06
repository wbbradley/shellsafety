# ShellSafety

ShellSafety is a safety gate for AI agent shell command execution. It parses
shell commands, classifies their effects (read-only, mutating, network,
executing), and evaluates them against a configurable policy to allow or deny
execution. It is designed to be used as a [Claude Code](https://docs.anthropic.com/en/docs/claude-code)
`PreToolUse` hook so that AI agents can run permitted commands without human
confirmation while dangerous commands are blocked before execution.

Derived from [ShellCheck](https://www.shellcheck.net/) by Vidar Holen, licensed
under [GPL-3](LICENSE).

## Quick Start

### Build and install

```sh
cabal build --allow-newer
cp "$(cabal list-bin shellsafety --allow-newer)" ~/.local/bin/
```

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

## Policy DSL Reference

A policy file is a sequence of directives, one per line. Blank lines and lines
starting with `#` are ignored.

### `assume <shell>`

Sets the shell dialect for parsing (e.g., `assume bash`). If omitted, the
shebang or default is used.

### `default allow` / `default deny`

Sets the fallback disposition when no rule matches. Default is `deny`.

### `allow [matcher...]` / `deny [matcher...]`

Rules are evaluated top-to-bottom; the **last matching rule wins**. Each rule can
have zero or more matchers. All matchers on a rule must match for the rule to
apply (AND logic). A rule with no matchers matches everything.

### Matchers

| Matcher | Description |
|---------|-------------|
| `command:<name>` | Matches when the command basename equals `<name>` |
| `effect:<category>` | Matches when the command's classified effect equals `<category>` |
| `arg:<literal>` | Matches when any argument exactly equals `<literal>` |
| `arg:/<regex>/` | Matches when any argument matches the regex |

## Effect Categories

ShellSafety classifies every command into one of five effect categories. In
pipelines, the most conservative (highest) effect wins.

| Effect | Description | Examples |
|--------|-------------|----------|
| `readonly` | Only reads data, no side effects | `cat`, `ls`, `grep`, `wc`, `git status` |
| `mutating` | Modifies files or system state | `rm`, `mv`, `chmod`, `git commit`, `apt install` |
| `network_out` | Sends data over the network | `curl -d`, `ssh`, `wget`, `git push` |
| `executing` | Runs arbitrary commands | `bash`, `sudo`, `python`, `find -exec` |
| `unknown` | Command not in the built-in database | Any unrecognized command |

Some commands are classified context-sensitively based on their arguments:

- **git**: `git status` is ReadOnly, `git push` is NetworkOut, `git commit` is Mutating
- **curl**: `curl <url>` (GET) is ReadOnly, `curl -d data <url>` is NetworkOut
- **find**: `find . -name '*.log'` is ReadOnly, `find -exec ...` is Executing, `find -delete` is Mutating

## Example Policy

```
# Parse commands as bash
assume bash

# Block everything by default
default deny

# Allow all read-only commands
allow effect:readonly

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
