# Phase 2 report — AST and taint

Phase 2 adds semantic filtering and bounded data-flow evidence while retaining
the lexical engine as an explicit fallback. It was implemented on top of Phase
1 commit `dee95cf`.

## Delivered

- Exactly pinned tree-sitter core and grammars cover C, C++, C#, Go, Java,
  Kotlin, JavaScript, TypeScript/TSX, PHP, Python, Ruby, Rust, and Swift.
- Successful parses restrict candidates to relevant call, assignment, and
  unsafe syntax nodes. Syntax errors, parser timeouts, incompatible grammars,
  or exhausted node/text budgets fall back to lexical analysis and increment
  parser fallback coverage.
- Intraprocedural taint models HTTP, CLI, environment, stdin, file-read, and
  deserialization sources; assignment propagation; sink-specific shell
  quoting; integer casts; parameterized-query behavior; and bounded allowlist
  guards. Unknown operations preserve taint.
- `--interprocedural` opts into one positional same-file direct-call boundary.
  Dynamic calls, imports, recursion, callbacks, fields, and deeper call chains
  remain outside the model.
- Findings JSON is now `apollyon.findings/v2`. Every finding includes `engine`,
  `confidence`, and `trace`; SARIF carries the same properties. Only modeled
  source-to-sink flows receive `tainted` confidence, with at most ten ordered
  evidence steps. Static output never uses `confirmed`.
- The nine CLI golden snapshots were deliberately updated. A structural check
  removed only the Phase 2 schema/coverage additions and normalized their text
  equivalents, confirming that Phase 1 content was otherwise identical.

## Fixed bounds

- Parser timeout: 2 seconds per file.
- AST nodes visited: 1,000,000 per file.
- Cumulative AST node text inspected: 16 MiB per file.
- Taint trace: 10 steps, with assignment history truncated to 8 before a sink.
- Interprocedural depth: one direct same-file call boundary when opted in.

These limits define the evidence produced. `candidate` and `tainted` remain
review states rather than exploitability verdicts.

## Dependency and compatibility decision

All direct parser dependencies use exact versions and the complete graph is
locked. During the minimum-version gate, the resolver-selected
`tree-sitter-language` 0.1.8 required Rust 1.90 even though the selected parser
interfaces remained compatible with 0.1.5. Pinning 0.1.5 avoids that unrelated
MSRV increase. Current locked transitive crates use edition 2024, so Rust 1.85
is the tested minimum and is enforced in CI and release validation.

## Verification

All target source was copied into disposable Docker storage with no host mount.
Validation ran as an unprivileged user with no network, a read-only root,
dropped capabilities, `no-new-privileges`, 2 CPUs, 3 GiB memory, 256 processes,
and bounded temporary storage. Dependency/toolchain preparation occurred in
separate images before source entered the network-disabled container.

Validated tool versions:

- Rust/Cargo 1.97.1 for the full quality gate.
- Python 3.11.2 for repository validators.
- Rust/Cargo 1.85.0 for the minimum-version gate.

Results:

- `cargo fmt --all --check`: passed.
- `cargo clippy --offline --locked --all-targets --all-features -- -D warnings`:
  passed.
- `cargo test --offline --locked --all-targets --all-features`: 81 passed,
  0 failed (54 unit, 11 golden/contract, 11 Phase 1, 5 Phase 2).
- `cargo build --offline --locked --release`: passed.
- Agent, integration, output-contract, and release-metadata validators: passed.
- `cargo +1.85.0 check --offline --locked`: passed.
- A complete self-scan covered 25/25 supported production-source files through
  the AST engine with no fallback or errors. Its five candidates were reviewed:
  four APO012 locations are the scanner's bounded input/output filesystem
  operations (including create-new output semantics and opened-file identity
  checks), and APO005 is the fixed `git` executable with an argument array and
  validated non-option reference. None advanced from candidate evidence to a
  validated defect.

The Phase 2 integration tests cover all supported grammar mappings, valid and
sanitized flows, opt-in interprocedural flow, syntax-error fallback, and removal
of function-definition substring false positives.

## Deferred

Observed execution, formal checking, fuzzing, case state transitions, and
remediation proof belong to Phase 3. No accuracy rate is claimed until the
versioned public-corpus benchmark work in Phase 4 is executed.
