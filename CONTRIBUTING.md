# Contributing

## Development Expectations

- Keep crate boundaries intact.
- Prefer additive changes over broad rewrites.
- Do not hardcode secrets, passwords, or bootstrap credentials.
- Treat Windows service/WFP and Linux routing changes as high-risk areas and document them clearly.

## Before Opening a PR

1. Run formatting and linting.
2. Run workspace tests.
3. Update docs for any operator-facing change.
4. Call out security-sensitive behavior changes explicitly.

Recommended commands:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

## Commit Guidance

- Use focused commits.
- Separate docs-only changes from behavior changes where practical.
- Include migration notes for config or schema changes.

## Security Reports

Do not open public issues for exploitable security problems. Use a private disclosure channel maintained by the repository owner.
