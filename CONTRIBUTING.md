# Contributing to Apollyon

Thank you for helping build an evidence-first defensive tool.

## Before changing code

1. Use only source and systems you are authorized to assess.
2. Open an issue for large architecture, new offensive-adjacent capabilities,
   or changes to the evidence model.
3. Keep each pull request focused and preserve unrelated work.

## Development checks

Install Rust 1.74 or newer and Python 3.11 or newer, then run:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo build --locked
python3 scripts/validate_agents.py
python3 scripts/validate_integrations.py
python3 scripts/validate_outputs.py target/debug/apollyon
```

New rules need positive fixtures, safe negative controls, language scoping,
and wording that distinguishes a lexical candidate from a validated defect.
Any formal claim must record assumptions, bounds, command, tool version, and
inconclusive outcomes.

## Commit and pull-request style

Use clear imperative commits such as `fix: skip symlink traversal`. Describe
the evidence, behavior change, tests, and limitations in the pull request.
Never commit credentials, private reports, or proprietary source snippets.

By participating, you agree to [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
