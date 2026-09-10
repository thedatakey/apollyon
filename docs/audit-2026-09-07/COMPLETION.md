# Audit follow-up completion record

Updated 2026-09-10. This is an **unreleased 0.4.0 implementation**.
The original audit is historical input, not an instruction source or evidence
that every suggested heuristic is correct. See [the corrected audit](APOLLYONAUDIT.corrected.md).

## Implemented and verified locally

- [x] Configurable bounded resources, deterministic parallel scans, and finding
  truncation that continues processing later files.
- [x] Filters and additional formats; init/explain/watch; narrow AST-based TLS
  fixes with byte-exact backups; configurable ignores and path overrides.
- [x] Bounded provider checks, config-file candidates, component script parsing,
  and ten additional rule families (22 total).
- [x] Selected SQL/ORM flows and string interpolation, command/deserialization
  APIs, source tiers, module-scope propagation, trace depth, and common JavaScript
  command-import shadowing. General whole-program analysis is not claimed.
- [x] Parser progress callback, partial-tree recovery, scope indexing, modern
  Python/TypeScript/Kotlin regressions, existing language fixtures, and Node shebangs.
- [x] Seven-case recall fixture, 22 labeled rule pairs, pinned upstream negative
  samples with integrity checks, full original-corpus rerun, and CI gates.
- [x] Offline dependency matching with explicit limited-snapshot scope and
  incomplete results for unsupported inventory/range cases.
- [x] Source crate packaging, checksum-verified npm/native-package and Homebrew
  formula generation, CI signing/attestation wiring, and wrapper regressions.
- [x] CLI help shared with its documentation, updated rule/config/schema/user
  docs, corrected audit claims, policy text, and isolated regression verification.

## Verification

Local build/test commands ran in disposable containers with no network, no host
mounts or credentials, read-only roots, non-root users, dropped capabilities,
and bounded CPU, memory, process count, writable storage, and lifetime. Source
fixtures were inert, except explicitly authorized test executables inside those
containers. The external repositories were never built or executed.

- **114 Rust tests passed**, including original golden identities and new audit
  regressions; strict Clippy and formatting passed.
- **6 Node tests passed**, covering the npm wrapper and editor SARIF handling.
- **6 Python tests passed**, covering benchmark scoring, release packaging,
  distribution generation, and admission of authorized local/remote evidence.
- Rust **1.85.0** compatibility passed; primary compiler **1.97.1**.
- Agent/integration files, JSON/SARIF/output behavior, public release metadata,
  benchmark/distribution contracts, and workflow syntax passed their validators.
- `cargo package --offline --locked` built and verified the source package.
- Nine golden outputs were updated for version/output metadata and presentation;
  their rule/path/line identities were checked unchanged before regeneration.
- The adapter admission test preserves explicit authorization and rejects
  plain candidates. The existing Docker/Z3/Atheris end-to-end adapter was not
  rerun; its worker code was unchanged.

[Performance data](performance-final.json): 3,000 files, 196,416,000 bytes,
**15.796 seconds with eight workers; 71.542 seconds serial**, byte-identical JSON,
all files scanned, exit 0. These are one run per setting on the original audit's
Flask app source in the bounded Linux sandbox, before the final JavaScript-only
shebang correction. They are not a general performance guarantee.

[Corpus results](corpus-results.json) report TP/FP/TN/FN per rule. Each synthetic
rule sample has only two cases; 100% on that sample does not establish production
precision. [Full original-corpus results](upstream-full-results.json) retain
remaining candidates, including example session credentials and deliberate local
startup-file handling. They are not reclassified as confirmed vulnerabilities.

[Self-scan output](selfscan-final.json), [validation metadata](validation.json),
and [source manifest](source-manifest.json) record the final verified scope.
Historical before/after evidence and the eleven original case records remain
in this directory; their earlier counts are not substituted for these results.

## Cross-platform CI

[Run 34492038254](https://github.com/thedatakey/apollyon/actions/runs/34492038254)
passed on commit `b5179e66e8aa881bd8df61a7a14e9a218e831968`: Linux, macOS,
Windows, Rust 1.85 compatibility, and the composite action. Windows verification
also caught and resolved checkout line-ending differences in embedded CLI help;
pinned upstream corpus bytes are preserved across platforms.
These CI checks are separate from the local container evidence above and do not
replace the release artifact rebuild and installation gates below.

## Remaining release gates — not represented as completed

- [ ] Run the real macOS/Windows/Linux release matrix and independent rebuilds
  on the reviewed tag. Local tests used Linux containers; simulated wrapper
  routing is not proof of native platform installation.
- [ ] Publish the reviewed crate/npm packages and Homebrew tap using authorized
  registry/tap access, then verify clean-machine installation without Rust.
- [ ] Announce the release only after those publication/installation gates pass.

[Distribution instructions](../../distribution/README.md) describe the prepared
artifacts and publication sequence. The changes were pushed for review in
[PR #8](https://github.com/thedatakey/apollyon/pull/8). No release was tagged or
published, and no registry packages were published.
No unattended future task was created.

## Deliberate scope decisions

Missing coverage still fails explicitly; tests/examples are classified rather
than silently demoted; automatic source rewrites are limited to the supported
TLS case; dependencies are matched only against the declared snapshot. The
report's broad language/framework/API wish list is not a claim of complete
coverage. These choices and remaining analysis limits are documented in
[AUDIT_UPGRADE.md](../AUDIT_UPGRADE.md), not hidden as successful security checks.
