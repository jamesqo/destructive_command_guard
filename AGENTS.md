# AGENTS.md

Keep this project small. Its purpose is a focused Claude Code/Codex command
guard, not a general policy platform.

## Scope

- Production code stays concrete: evaluator, hook adapter, CLI.
- Add a rule only for a destructive operation with a clear false-positive
  boundary.
- `.dcg.toml` may only add literal project denials. Do not add allow rules,
  inheritance, profiles, plugins, remote includes, or bypass credentials.
- Do not add packs, registries, databases, history, analytics, TUI, MCP,
  self-update, network access, or a general configuration framework.
- Backward compatibility with removed product surfaces is not required.

## Rust

- Stable Rust 2024; Cargo only; unsafe code is forbidden.
- Avoid new dependencies when the standard library is sufficient.
- External input errors must be handled without panics.
- Add paired deny and allow tests for evaluator changes.

## Quality gates

```bash
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo nextest run       # cargo test is an acceptable fallback
```

Work on `main`. After pushing `main`, mirror it with:

```bash
git push origin main:master
```
