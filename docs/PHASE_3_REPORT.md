# Phase 3 report — bounded evidence and remediation

Phase 3 adds an authorized case workflow for tainted findings and one narrow,
end-to-end Python eval adapter. Static scanning remains separate from target
execution.

## Delivered

- `--cases-dir <new-directory> --authorized` creates private, create-new
  `apollyon.case/v1` candidate records for tainted findings. Optional repository
  and revision identifiers capture scope. Findings reference their cases.
- The Docker controller rejects unauthorized or mismatched cases, escaping or
  symbolic-link paths, oversized snapshots, reused output paths, and missing or
  mislabeled tools images.
- Before receiving target bytes, each case container is inspected for no
  network, no mounts, a read-only root, an unprivileged user, dropped
  capabilities, `no-new-privileges`, and CPU, memory, process, storage, and
  wall-time bounds.
- The `python-eval/v1` adapter reproduces one function-local tainted APO004
  flow, proposes an `ast.literal_eval` diff on a disposable copy, reruns the
  original payload, verifies a literal regression, and runs local unittest
  discovery.
- Optional Z3 evidence proves only the recorded replacement call's syntax
  identity under its two-value model. Optional Atheris evidence compares the
  original and patched copies for a 1–5 second budget and records the controlled
  crash input. Both adapters record exact versions and bounds.

## Verified end-to-end case

The checked-in fixture advanced through `candidate → validated → remediated →
verified`. The original payload created the sandbox marker; the proposed patch
blocked it; the literal regression and existing unittest passed. Z3 4.15.3
returned `unsat` for the bounded conflicting-call model. Atheris 3.0.0 produced
one crash artifact and exit 77 on the original seed, then zero artifacts and
exit 0 on the patched copy in one second. The host fixture's SHA-256 remained
unchanged.

The executed tools image ID was
`sha256:57a14580def45a5ca894dc0add9566e6f7ab5bdfab8bc8cfedcc58324b0ad737`,
built from the Dockerfile's pinned Python base digest. This ID records this
validation run; independent rebuilds may differ because transitive Debian
packages are not locked by digest.

## Bounds and limitations

The adapter supports a zero-argument function using `input()` or one positional
argument, a single mapped eval call, one controlled reproducer payload, and
Python unittest discovery. It does not establish safety for arbitrary inputs,
other calls, or the entire program. Concurrent mutation of the copied source
tree remains outside the controller's guarantee.

## Quality evidence

Rust unit and integration coverage includes candidate creation, authorization
failure, case references, and create-new behavior. Exact text, JSON, and SARIF
snapshots remain enforced; their only intentional Phase 3 change is the scope
sentence describing AST validation and lexical fallback.

The isolated checkpoint passed `cargo fmt --all --check`, Clippy with all
targets/features and warnings denied, all 83 Rust tests, the locked release
build, Rust 1.85 `cargo check`, and the agent, integration, output-contract, and
release-metadata validators. The Python controller and workers passed bytecode
compilation and the end-to-end sandbox run described above.

Static self-scans covered all 26 Rust and 9 Python production files with the AST
engine, no parser fallback, and complete accounting. The six Rust and thirteen
Python results were reviewed as expected boundaries in scanner file I/O,
create-new report/case handling, fixed subprocess invocations, sandbox control,
and the controlled local marker payload. This review did not advance those
candidates to validated defects.
