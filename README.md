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

## Gas City approvals

One-shot approval for a blocked destructive command belongs in Gas City, not in
`dcg`. The guard remains a static classifier and must not grow reusable bypass
environment variables, persistent allowlists, profiles, plugins, or general
policy inheritance.

The Gas City primitive should expose this operator flow:

```console
$ gc approval request --rig <rig> --session <session-id> --cwd <path> --ttl 5m --reason <text> -- <argv...>
$ gc approval approve <request-id> --ttl 5m --reason <text>
$ gc approval exec <permit-id> -- <argv...>
$ gc approval show <request-or-permit-id> --json
$ gc approval revoke <permit-id>
```

Gas City, not `dcg`, owns request storage, human approval authority, permit
creation, revocation, and audit. A permit must bind to the exact canonical argv
bytes and SHA-256, rig identity, requester/session, working directory when
relevant, and a short expiry. `gc approval exec` must recompute the argv hash
and verify the permit id, rig, requester/session, cwd, expiry, and unused state.
It must then durably write the consume audit and atomically mark the permit
consumed before it execs the exact argv. Stale, mismatched, replayed,
already-consumed, malformed, or wrong-rig/session permits must fail closed.

DCG-side behavior is intentionally limited: the approved wrapper command is
ordinary shell input to the classifier. DCG must not inspect the wrapped argv as
a reason to add a broad bypass, and it must continue to deny the destructive
command when it is invoked directly or with a reusable-looking environment
variable.

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

## Automatic deployment

Every push to `main` runs `.github/workflows/deploy.yml`. GitHub Actions builds
the static Linux binary, cross-compiles the Apple Silicon binary with
`cargo-zigbuild`, and deploys `dcg` atomically to `~/.local/bin` on Xenia,
`dev-macbook`, and `personal-macbook` over Tailscale. Destination machines do
not need the repository or a Rust toolchain. Manual runs are also available
through `workflow_dispatch`.

The repository needs the same deployment secrets as Veritas:
`TS_OAUTH_CLIENT_ID`, `TS_OAUTH_SECRET`, `DEPLOY_SSH_PRIVATE_KEY`, and
`DEPLOY_SSH_KNOWN_HOSTS`.
