# Phase 4 report — measured quality and distribution

Phase 4 publishes reproducible measurements and adds the requested adoption and
release surfaces. The implementation is complete in source; actual signed
release artifacts exist only after a maintainer approves and pushes the v0.3.0
tag and the release workflow succeeds.

## Benchmarks

The benchmark manifest pins OWASP Benchmark commit
`51f0a7cf8bb9d17ce1f6d72598c1d1c6ce90f661`, the official NIST SARD Juliet
C/C++ 1.3 archive with its published SHA-256, nine selected Juliet files with
individual hashes, and the vulnerable/fixed PPTAgent revisions linked from
CVE-2026-42079. Fetching, scoring, ground-truth units, and raw metric counts are
committed and deterministic.

The isolated run scanned 2,740 OWASP Java files, nine Juliet C files, and both
CVE Python revisions with complete AST coverage and no parser fallback. The
published tables retain low recall, false positives, undefined precision, and
unscored findings. See [BENCHMARKS.md](BENCHMARKS.md) for every denominator and
reproduction command.

## Adoption surfaces

- The composite GitHub Action builds its exact referenced source, accepts
  `path`, `fail-on`, and `baseline`, creates SARIF, optionally uploads through a
  commit-pinned GitHub CodeQL action, and propagates Apollyon's exit code after
  upload.
- `.pre-commit-hooks.yaml` installs the Rust project through pre-commit and runs
  one whole-repository scan without duplicating work per filename.
- `vscode-apollyon` parses SARIF 2.1.0 and renders workspace-relative results as
  VS Code diagnostics. It rejects absolute and parent-traversing locations and
  includes parser true/false tests using Node's built-in runner.

## Release hardening

The release workflow builds each native target twice in independent target
directories and rejects differing binaries. A repository-owned packager fixes
archive ordering, owners, modes, and timestamps. The final job creates one
deterministic checksum manifest, signs it keylessly with Cosign 3.1.2, and uses
GitHub's `actions/attest` provenance mode with the checksum manifest as the four
archive subjects. Every external Action remains pinned to a full commit.

Local packaging tests prove repeatable tar.gz and zip bytes for identical
inputs. Workflow signing, OIDC certificate identity, hosted-runner rebuilds,
and public download verification cannot be truthfully marked passed until the
tag workflow runs. [RELEASING.md](RELEASING.md) defines that final gate and
[INSTALL.md](INSTALL.md) gives both Cosign and GitHub attestation commands.

## Validation record

The final source snapshot passed the required gates in network-disabled,
read-only, unprivileged containers with no host mounts, all Linux capabilities
dropped, and bounded CPU, memory, process count, and wall time:

- Rust 1.97.1: formatting, Clippy with warnings denied, 84 unit/integration
  tests, and the release build.
- Rust 1.85.0: the locked minimum-version check.
- Five agent definitions, portable integrations, JSON/SARIF/output behavior,
  release metadata, Phase 4 contracts, two benchmark scorer tests, and the
  two release packaging/checksum tests.
- Node.js 22.22.0 from official image digest
  `sha256:dd9d21971ec4395903fa6143c2b9267d048ae01ca6d3ea96f16cb30df6187d94`:
  syntax checks and four SARIF/path-confinement tests.
- GitHub workflow syntax passed actionlint 1.7.12 from official image digest
  `sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667`.
- A snippet-free static self-scan completed across 59 AST files with no lexical
  or parse fallback and reported 49 review candidates. That result is an audit
  input, not a security verdict.

The first live fetcher check reached OWASP successfully but NIST rejected
Python's default user agent with HTTP 403. The fetcher was corrected to send an
explicit Apollyon user agent; a second clean fetch then downloaded and verified
all three pinned corpora and every recorded hash. No corpus code, build, test,
hook, package manager, or dependency was executed.
