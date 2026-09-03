# Phased upgrade plan

This plan implements Tom Koentjes's supplied `CODEX_BUILD_INSTRUCTIONS.md`.
It records sequencing and decisions needed to make that specification concrete.
Work proceeds one phase at a time, with quality gates, a commit, and an
end-of-phase report before the next phase. Later phases below are planned,
not implemented capabilities.

## Phase 0 — Library foundation

Extract modules, preserve every existing test, capture pre-refactor output,
and document the pipeline. Use the latest main commit (`d1dc52e`) as the
baseline, preserving its C# proximity fix and scope note.

Deliverables: [architecture](ARCHITECTURE.md), library/thin binary, per-module
unit tests, nine golden snapshots, CLI contract integration tests, and
README/changelog updates. No new rules, flags, output fields, or dependencies.

## Phase 1 — Lexical rules and adoption controls

Implemented; see [the phase report](PHASE_1_REPORT.md) and [CONFIG.md](CONFIG.md).

Implement in this order within the phase, with focused tests for each step:

1. Extend lexical output to retain bounded literal/comment metadata while
   preserving the existing sanitized-code view. Secret, crypto, and SQL rules
   cannot inspect literals after the current sanitizer has erased them.
   Suppression directives must be recognized only in real comments, never in
   strings. Do not store secret values in report messages, traces, or baselines.
2. Add APO007–APO012 and auditable pattern tables. Include both positive and
   negative fixtures per supported language; retain candidate wording. Pin
   thresholds for secret lengths/entropy in tests. Do not expand vague patterns
   into unsupported semantic claims.
3. Add rule-specific and all-rule same-line suppressions, with explicit counts.
   Defer optional next-line block-comment suppression unless its scope is
   specified and covered by tests.
4. Add baseline read/write with a documented deterministic fingerprint format,
   normalized relative paths, bounded input, and new/baselined/total counts.
   Do not use Rust's unspecified default hash or store raw matched lines.
   Specify duplicate-line and stale-baseline behavior before implementation.
5. Add changed-file selection. Use argument arrays for Git, robust filename
   handling, and explicit handling of additions, renames, and deletions.
   Reject paths outside the root. Git failures and omitted files must remain
   visible in coverage.
6. Add bounded `.gitignore` support and `apollyon.toml`, with a documented
   supported syntax and precedence: built-in defaults, config, then explicit
   CLI values. Unsupported/malformed syntax must be reported. Keep the
   zero-runtime-dependency goal unless a justified exception is necessary.

Golden changes in this phase must be deliberate. Preserve findings v1 and
existing fields; add summary fields compatibly. Write `docs/CONFIG.md` and
rule/control documentation before the phase checkpoint.

## Phase 2 — AST and taint

Implemented; see [the phase report](PHASE_2_REPORT.md) and [FINDINGS_SCHEMA.md](FINDINGS_SCHEMA.md).

Add exactly pinned tree-sitter versions and grammars in the requested order:
Python, JS/TS, Go, C/C++, then the remaining languages. Define a per-language
coverage matrix rather than implying all languages gain semantic support at
once. Parse failures and unsupported grammars use the lexical fallback and
remain visible in coverage.

Keep engine selection deterministic and avoid duplicate AST/lexical findings.
Model assignments, branches, calls, and source-to-sink traces within explicit
bounds. Sanitizers must be sink-specific: shell quoting does not make SQL or
paths safe, and parameterization applies only to the relevant query arguments.
Unknown behavior must not silently clear taint. Test both unsanitized flows
and correctly sanitized flows, including branch joins and aliases.

Add bounded, opt-in interprocedural analysis after the intraprocedural model
passes. Record depth/module limits and analysis gaps. Bump to findings v2 with
`engine`, `confidence` (`candidate` or `tainted`), and `trace`, documenting the
v1 migration. Taint is not proof of exploitability.

## Phase 3 — Bounded evidence and remediation

Implement the case state machine and sandbox boundary before executing any
reproducer. Require explicit target authorization, no network or host secrets,
no host mounts, disposable storage, bounded CPU/memory/processes/wall time,
and fail-closed checks. Separate target execution from static scanning.

Start with one small end-to-end fixture and one adapter. An observed reproducer
failure is evidence only for the recorded claim. A reproducer that does not
trigger is not proof of safety. Preserve candidate or report inconclusive with
the reason when validation cannot decide the claim.

Add opt-in formal/fuzz adapters with pinned tool versions, exact bounds, and
reproduction artifacts. Propose minimal remediation plus regression coverage
only after validation. Independently re-run the original case and regressions
before marking verified. Emit a reviewable patch; never silently modify or
commit a target project. Follow [CASE_SCHEMA.md](CASE_SCHEMA.md).

## Phase 4 — Measured quality and distribution

Define labeled corpus versions, language/rule mappings, and counting rules
before benchmarking. Keep unsupported cases and analysis failures visible;
publish measured precision/recall/false-positive rates with denominators and
reproduction commands, not aggregate marketing estimates.

Build and test the Action, pre-commit integration, and VS Code viewer against
the established CLI/schema contract. Extend the existing release workflow
with signing and verification; inspect its current checksums and attestations
before adding overlapping machinery. Signed artifacts require actual release
execution and verification before being described as delivered.

## Quality gates and checkpoints

Each phase runs formatting, Clippy with warnings denied, all tests, and a
release build, preserving the locked dependency graph. Also run the existing
agent, integration, output-contract, and release-metadata validators. Record
tool versions, commands, results, limitations, and deferred work.

Under this project's execution policy, builds/tests run in a disposable
isolated environment. Copy source into it; do not mount the checkout or host
credentials. Prepare trusted toolchain dependencies separately before placing
target source in the network-disabled execution environment.

Stop at each phase checkpoint. The next phase is not complete until every
acceptance criterion in the supplied build specification has evidence.
