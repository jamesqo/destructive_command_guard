# destructive_command_guard

`dcg` is a small pre-execution guard for Claude Code and Codex. It blocks a
focused set of shell commands that are likely to destroy source code,
uncommitted Git work, or filesystems.

It is intentionally a guardrail for well-intentioned agents, not a security
boundary. The entire production implementation is three Rust files and its only
runtime dependencies are `serde` and `serde_json`.

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

## Retained rules

- destructive Git reset, clean, checkout, restore, branch deletion, stash,
  reflog, and object-pruning operations;
- recursive `rm`, `find -delete`, `shred`, zero-length truncation, filesystem
  formatting, and `dd` output targets;
- common recursive PowerShell and Windows deletion forms;
- shell command composition, common wrappers, and `sh -c`-style nested scripts.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo nextest run       # or: cargo test
```

The default branch is `main`; `master` mirrors it for legacy links.
