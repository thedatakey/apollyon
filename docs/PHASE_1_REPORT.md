# Phase 1 completion report

Date: 2026-09-03. Baseline: Phase 0 commit `55d186f`.

Delivered APO007–APO012 with positive/negative fixtures and language-specific
unit cases; comment-only same-line suppressions; SHA-256 baseline read/write;
changed-file lists and bounded Git diff selection; bounded nested `.gitignore`
handling; `apollyon.toml` and CLI overrides. No runtime dependencies were added.

New flags: `--baseline`, `--write-baseline`, `--changed-files`, `--diff`,
`--no-gitignore`, `--enable-rule`, `--disable-rule`, and `--severity`.
New additive v1 output includes fingerprints, suppression/disable/baseline
counts, total/new candidates, and file-selection coverage. See
[CONFIG.md](CONFIG.md), [RULES.md](RULES.md), and [FINDINGS_SCHEMA.md](FINDINGS_SCHEMA.md).

Secret-candidate lines remain redacted even for other findings on that line and
when secret detection is disabled. Baselines contain identifiers only. Incomplete
scans do not write baselines. All filtering is counted; none implies safety.

## Checks

All 70 tests passed: 48 unit, 11 golden/library/CLI, and 11 Phase 1 integration
tests. Formatting, Clippy with warnings denied, release build, and all existing
agent/integration/output/release validators passed. The gates were:

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

Execution used the prepared Rust 1.97.1/Python 3.11.2 Linux ARM64 image,
network disabled, no host mounts or secrets, read-only root, unprivileged UID,
capabilities dropped, no-new-privileges, 2 CPUs, 2 GiB memory/no additional swap,
128 processes, 1 GiB workspace and 128 MiB temporary storage. Individual gates
were limited to 60/180 seconds; the disposable container lifetime was four hours.
No target code or build/test hooks were executed on the host.

Golden updates were deliberate: removing only the new fields and six new SARIF
registry entries reproduced the exact previous JSON/SARIF content. Text output
preserved all old bytes and appended the accounting line. New snapshots then
passed exact-output tests.

## Limits

This phase remains lexical. Same-line associations are not dataflow. The precise
TOML/gitignore subsets and rule limitations are documented; unsupported ignore
syntax produces an incomplete scan. Next-line block suppression was optional
and is not implemented. Git diff does not include untracked files. Missing and
unsupported selected paths are counted explicitly. Baseline duplicates share
an identity, and hashes are not encryption. Windows/macOS and minimum-Rust
execution remain CI checks, not locally verified claims.

Phase 1 acceptance criteria are satisfied within the explicitly permitted
bounded lexical/config/ignore scope. Phase 2 semantic analysis is next.
