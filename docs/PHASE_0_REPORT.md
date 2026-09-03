# Phase 0 completion report

Date: 2026-09-03. Baseline: `d1dc52e6a200d35c2dc974bfd4e1234276313681`.
Branch: `codex/phase-0-library`.

## Delivered

- Library crate and four-line binary entry point.
- Cohesive CLI, lexer, scanner, report, display, rule-family, and render modules.
- All 35 original tests moved into module test suites without changing their
  inputs or assertions.
- Nine exact pre-refactor CLI snapshots and 11 integration tests covering
  output, exit codes, and library rendering parity.
- Architecture and upgrade-plan documents, README/changelog updates, and LF
  checkout rules for byte-stable fixtures.

New CLI flags, detection rules, output fields, and runtime dependencies: none.
Findings v1, SARIF, version 0.2.0, and existing resource bounds are preserved.

## Validation

The original unmodified baseline was built and tested first: 35 tests passed.
The nine snapshots were captured directly from that executable, before the
refactor. The refactored executable matches every snapshot byte for byte.

All commands below passed using Rust 1.97.1, Cargo 1.97.1, and Python 3.11.2
on Linux ARM64 in a disposable Docker container:

```sh
cargo fmt --all -- --check
cargo clippy --offline --locked --all-targets --all-features -- -D warnings
cargo test --offline --locked --all
cargo test --offline --locked --all-targets --all-features
cargo build --offline --release --locked
python3 scripts/validate_agents.py
python3 scripts/validate_integrations.py
python3 scripts/validate_outputs.py target/debug/apollyon
python3 scripts/validate_release.py
```

Results: 35 unit tests and 11 integration tests passed; doc tests contain no
cases. Formatting, linting, release compilation, and all four Python validators
passed. `git diff --check` passed on the host checkout.

Execution controls: no network, no host mounts or host credentials, read-only
container root, UID/GID 1000, all capabilities dropped, no-new-privileges,
2 CPUs, 1 GiB memory with no additional swap, 128 processes, 512 MiB workspace
and 64 MiB temporary storage. Each gate used a 60- or 180-second timeout;
container lifetime was capped at one hour. Source was copied in as an archive.
Toolchain preparation happened separately, before target execution.

The toolchain image used the Rust base digest
`sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97`
with rustfmt, Clippy, and Python available. No target build, test, fixture,
hook, or package-manager command ran on the host.

## Limits and next checkpoint

Compatibility evidence covers the preserved tests and checked-in fixtures,
not every possible input. Windows/macOS execution and the then-current Rust 1.74 minimum
version check were not run locally; the existing CI jobs cover those platforms
and the minimum version. No new language features or dependencies were added.

Phases 1–4 remain deferred, as required by the supplied one-phase-at-a-time
workflow. Phase 1 starts with bounded literal/comment metadata before adding
rules and suppression controls. See [UPGRADE_PLAN.md](UPGRADE_PLAN.md).
