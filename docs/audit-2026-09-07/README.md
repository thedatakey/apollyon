> Historical first-pass report. The follow-up requested by the user is now
> recorded in [COMPLETION.md](COMPLETION.md) and
> [the corrected audit](APOLLYONAUDIT.corrected.md). The counts, timings, and
> “remaining work” below describe the earlier snapshot, not the current checkout.

# External audit review and fixes — 2026-09-07

Reviewed the entire supplied `APOLLYONAUDIT.md` against working-tree base
`c18edd8c5272cf5d04fbdc08d9fff347bfb800af`. The supplied report audited a
different revision (`a451602`). Its proposed work plan is an external proposal,
not independent evidence or authorization to publish packages.

## Verified corrections

| Report section | Result |
| --- | --- |
| 1.1, 1.3 | Common `**` and character-class ignore patterns work. Unsupported positive patterns are skipped individually, retain supported rules, and produce bounded path/line notes. Unsupported negations remain coverage errors because re-inclusion can change coverage. |
| 1.2 | CLI-generated multiline usage is readable; target-derived text still escapes newlines, terminal escapes, and bidi controls. |
| 1.4 | Identical findings on different lines get distinct occurrence fingerprints; unrelated line insertions preserve them. Existing first-occurrence fingerprints remain compatible. |
| 2.1 | Secret name segments and immediate literal assignment replace the broad name/any-literal association. Standalone entropy is removed; common placeholders are excluded. Provider prefixes are expanded, with length/character checks, not claimed checksum validation. |
| 2.2 | Ordinary variable file paths are no longer findings. APO012 requires modeled input flow; bare `open` no longer matches unrelated method receivers. |
| 2.3 | Tracked first SQL arguments reach supported sinks across lines. Bound parameter values and a subsequent constant overwrite do not trigger these checks. This is not general SQL/ORM analysis. |
| 2.4 | Node child-process direct require, namespace require/import, and destructured/named imports with aliases are recognized. Shell execution and argv forms receive differentiated severity. Not every proposed runtime/API was added. |
| 2.5 | Explicit Python `usedforsecurity=False` suppresses APO008. |
| 2.7 | File/deserialization reads no longer become implicit sources. Sink-first-argument checks avoid treating input in unrelated parameters as a path/SQL input. Remote/local confidence tiers are not implemented. |
| 2.8 | Recovered trees preserve valid AST expressions; damaged expressions are lexical and have no taint claim. Parser error-node counts and notes are exposed. |
| 4.1 | The finding cap no longer stops later files from being analyzed. Omitted findings are counted; incomplete output still returns exit 3. Other resource caps remain enforced. |
| 4.2, 5 | Removed repeated rule lexing from the AST walk and the separate rule-ID registry. Call lookup uses sorted line ranges. AST node and captured-text bounds remain. |
| 6 | Added precision/recall regression tests and updated configuration, rule, architecture, and output-contract documentation. |

These are scanner behavior corrections. They are not validated vulnerabilities
in any scanned application. Durable per-cause evidence records are in `cases/`.

## Audit claims corrected or qualified

- The Git polling loop already sleeps for 10 ms. No busy-spin fix was needed.
- `--enable-rule` already has coherent documented semantics: re-enable a
  disabled rule and add it to a configured allowlist. Without an allowlist,
  all registered rules are already enabled.
- Source and sink may correctly share a line: `open(request.args['f'])`.
  Eliminating all same-line traces would remove valid evidence.
- An oversized supported file or truncated result is a coverage/output gap.
  It must not be labeled complete merely to obtain exit 0. Users can explicitly
  exclude generated content when it is outside their intended scope.
- A test/example location alone does not establish that a finding is false or
  harmless. Automatic severity demotion and production-only failure thresholds
  were not adopted.
- Static taint is modeled input flow, not verified attacker reachability.
  Local CLI/environment/stdin sources still exist; the output must not describe
  all `tainted` findings as remotely exploitable.
- The report's three-repository precision percentages lack pinned repository
  revisions and a checked-in labeled adjudication corpus. They were not
  independently reproduced here and must not be presented as measured current
  precision. The reported 4/7 score likewise remains historical; the patched
  synthetic regression is 7/7.
- Parser age alone does not prove that particular modern syntax is unsupported.
  Partial recovery is tested, but the proposed modern-syntax matrix was not run.
- The sandbox runner already supplies the listed network, capability, user,
  process, memory, read-only-root, and time controls. No blanket hardening claim
  or unsolicited modification was made.
- No minimum provider length/charset heuristic proves that a key is real, valid,
  or compromised. Redacted candidate semantics remain essential.

## Verification

All target builds/tests ran on disposable copied source in Docker:

- Image: `sha256:240a5dade4cd19a83f8023c2f5598c6dc2c68e76f9c5ef71ccf41010e926dd2e`.
- Network disabled; no host mounts or host secrets; read-only root; UID/GID
  65532; all capabilities dropped; no new privileges.
- Four CPUs, 4 GiB memory/swap bound, 256 processes, 3 GiB `/work` tmpfs,
  256 MiB `/tmp`; CPU-time limit and per-command wall-time limits.
- Fixture source was scanned, never executed.

Passed: 92 Rust tests (`cargo test --offline --locked --all-targets
--all-features`), strict Clippy, formatting, 2 Python packaging tests, and agent,
integration, release-metadata, JSON/SARIF/output validators. Original golden
output snapshots remained unchanged.

`before.json` and `after.json` capture nine focused checks against separately
compiled unchanged and patched binaries: eight initially failed; all now pass.
`tests/audit_regressions.rs` supplies eight checked-in regression tests including
seven-case recall, negative precision examples, imports, ignore diagnostics,
terminal safety, occurrence fingerprints, and finding-limit accounting.

`performance.json` records one debug-build run per binary on the same inert
40-file, 2,347,600-byte synthetic Python corpus: 9.646 s original versus 8.084 s
patched. Both scans completed with identical zero-finding coverage. This is
about 16% faster in that measurement, not the proposed >50% target or the
3,000-file/8-core release benchmark. Parallel scanning has not been implemented.

The repository-copy self-scan returns exit 0 and `complete: true`. Its remaining
findings are review candidates, not a clean-security verdict. See
`selfscan-summary.json` for coverage and exclusions.

## Remaining work from the proposal

Not implemented or claimed complete: configurable scan caps, parallel workers,
full provider checksums/prefix coverage, general ORM/raw SQL tracking, broader
execution/crypto/deserialization APIs, source confidence tiers, module-scope
taint inheritance, full trace-depth reporting, complete import shadowing,
modern-syntax language fixtures, parser progress-callback migration, and pinned
third-party precision corpora.

P2/P3 distribution publishing, init/fix/explain/watch, new output formats and
flags, configurable default ignores, per-path configuration, config-file and
new-language scanning, additional rule families, dependency scanning, UI/README
redesign, security response commitments, and published precision/recall remain
product/release work. They were not silently treated as required fixes or shipped
as unverified heuristics. The original report should not be read as evidence
that those roadmap items are already delivered.
