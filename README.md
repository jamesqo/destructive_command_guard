# destructive_command_guard

`dcg` is a small pre-execution guard for Claude Code and Codex. It blocks a
focused set of shell commands that are likely to destroy source code,
uncommitted Git work, or filesystems.

It is intentionally a guardrail for well-intentioned agents, not a security
boundary. The entire production implementation is three Rust files and its only
direct runtime dependencies are `serde`, `serde_json`, and `toml`.

## Use

Point a Claude Code or Codex `PreToolUse` shell hook at the `dcg` binary. Hook
requests are read as JSON from stdin. Safe commands produce no output; blocked
commands produce the minimal denial envelope accepted by both clients.

Evaluate a command manually without running it:

```console
$ dcg test --json "git reset --hard HEAD~1"
{"command":"git reset --hard HEAD~1","decision":"deny","rule_id":"git.reset-destructive","reason":"git reset can discard uncommitted changes"}

$ dcg test "git status"
ALLOW
```

`dcg test` exits `0` for allow, `1` for deny, and `2` for usage or I/O errors.

## Project rules

The nearest `.dcg.toml`, searched from the command's working directory up to
the Git root, may add project-specific denials:

```toml
[[deny]]
id = "no-prod-deploy"
prefix = "deploy production"
reason = "production deploys require the release workflow"

[[deny]]
id = "protect-account"
contains = "--account production"
reason = "production account operations require review"
```

Each rule requires `id`, `reason`, and exactly one matcher:

- `exact`: matches the entire trimmed command;
- `prefix`: matches a command prefix at a shell or argument boundary;
- `contains`: matches a literal substring.

Project policy is deliberately deny-only. It cannot disable a built-in rule,
approve a command, load plugins, include another file, or define reusable
bypasses. Invalid or unreadable policy fails closed as
`project-config.invalid`. Only the nearest file is used; policies do not merge
or inherit.

## Retained rules

- destructive Git reset, clean, checkout, restore, branch deletion, stash,
  reflog, and object-pruning operations;
- recursive `rm`, `find -delete`, `shred`, zero-length truncation, filesystem
  formatting, and `dd` output targets;
- common recursive PowerShell and Windows deletion forms;
- shell command composition, common wrappers, and `sh -c`-style nested scripts;
- deny-only repository rules from `.dcg.toml`.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo nextest run       # or: cargo test
```

The default branch is `main`; `master` mirrors it for legacy links.
