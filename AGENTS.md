# AGENTS.md

## Project Overview

- Rust workspace for secure multi-party computation(SMPC).


## Commands

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

## Git

- Use Conventional Commits for commit messages:
  - `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- Use branch names like `feat/xxx`, `fix/xxx`, `docs/xxx`, `refactor/xxx`,
  or `chore/xxx`.
- Run the test suite before opening a PR.
