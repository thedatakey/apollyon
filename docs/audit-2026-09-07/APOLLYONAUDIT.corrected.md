# Apollyon audit — corrected findings and current status

Updated 2026-09-09. The supplied external report concerned commit `a451602`.
The fixes were made against the existing checkout based on
`c18edd8c5272cf5d04fbdc08d9fff347bfb800af`, preserving prior work. The original
file in Downloads is retained as historical evidence. This document distinguishes
observed defects, proposed features, and claims that need qualification.

## Confirmed defects addressed

The earlier before/after tests and case records document ignore-file handling,
readable usage errors, duplicate-finding fingerprints, credential assignment
matching, the Python nonsecurity hash marker, flow-gated paths and SQL,
JavaScript command imports, AST recovery/registry handling, and finding-cap
accounting. Their regression tests still pass. The seven planted cases remain
7/7. `complete` remains a coverage statement, never a security verdict.

The follow-up adds configurable resource bounds and deterministic parallel
scanning, path policy overrides and classification, local/remote confidence
levels, module-source propagation, trace depth, raw SQL wrappers and string
interpolation, component scripts, config-file candidates, and modern-syntax
regressions. New workflows include init, explain, watch, narrow TLS fixes,
filters and CI/Markdown outputs, offline advisory matching, and package-manager
artifact generation. See [the implementation guide](../AUDIT_UPGRADE.md) for
exact supported patterns and limits; a rule-family name is not comprehensive
framework coverage.

## Corrections to the external brief

- **A lexical match is a candidate.** Counting all candidates as vulnerabilities,
  or all test/example matches as false positives, does not establish measured
  vulnerability precision. Exploitability and intended usage need separate
  labels and validation. No claim of “0/60 vulnerability precision” is adopted
  without those labels.
- **Incomplete coverage must stay incomplete.** A skipped oversized file or
  omitted findings cannot yield a clean result. Unsupported ignore syntax is a
  note because the scanner keeps scanning extra files; genuinely unreadable or
  unprocessed input still produces exit 3. Finding limits no longer stop later
  files from being processed.
- **The git wait-loop claim was stale for this checkout.** Its existing loop
  already sleeps for 10 ms and rejects option-like refs. No redundant change
  was needed.
- **Grammar version age does not prove a syntax failure.** Partial-tree recovery
  and modern Python, TypeScript, and Kotlin examples are tested. Existing
  language fixtures remain covered; this does not promise all language versions.
- **Not every provider-shaped value is a secret.** JWT strings and Twilio account
  identifiers alone do not establish credential exposure. Provider matching
  never validates a token against a service. The original unconditional-prefix
  proposal would introduce false positives.
- **Deserialization APIs require version/context precision.** PyTorch documents
  `weights_only=True` as the default from 2.6 when no `pickle_module` is supplied.
  The added rule detects explicit `weights_only=False`; it does not label every
  `torch.load` call unsafe. `yaml.full_load` is not treated as equivalent to
  unrestricted Python object construction.
- **Local data is not automatically remote attacker input.** Modeled argv/env
  flows are `reachable`, while modeled remote request flows are `tainted`.
  Flask's deliberate `PYTHONSTARTUP` file loading is a local path-flow candidate,
  not a validated traversal vulnerability.
- **Test paths are context, not a safety guarantee.** Automatic severity demotion
  is not applied. `--production-only` supports focused review and CI thresholds
  explicitly. A literal session secret in an example may still be useful to flag
  when copied into an application.
- **Automatic fixes are narrow.** Shell argument rewriting, cryptographic
  migrations, and SQL parameterization can change semantics. Only the tested
  Python requests certificate-verification change is automated, using AST
  keyword arguments, byte-exact backups, and create-new temporary files.
- **An offline database is only as broad as its snapshot.** The embedded four
  selected advisories are explicitly identified; zero matches cannot be called
  dependency security clearance. Custom reviewed snapshots are supported.
- **Distribution implementation is not publication.** Source packaging and
  npm/Homebrew generation are tested; real registry/tap publication and
  cross-platform installation are still release gates.

## Measurements

[Final performance data](performance-final.json) records 3,000 copies of the
original audit's Flask `src/flask/app.py`: 196,416,000 bytes in total. Both worker
settings process all 3,000 files, complete successfully, and produce byte-identical
JSON. The eight-worker result meets the proposed 20-second target in this isolated
Linux environment. These are single-run local measurements, not a portable SLA.

[Per-rule results](corpus-results.json) contain 22 positive/negative synthetic
pairs, all passing, and three pinned source-file negative samples for APO007 and
APO012. The sample is too small to estimate production precision. The original
seven-case recall is an additional independent regression fixture.

[Full original-corpus results](upstream-full-results.json) retain actual candidates
and coverage, including example credentials and intentional development behavior.
Those counts are not reported as vulnerabilities. The original local snapshots
used for this rerun were:

| Project | Revision |
| --- | --- |
| pallets/flask | `d318b683471101618febed18996405ad26462110` |
| psf/requests | `dae7ef63b4df6eded86637f251fc4e3a06c3b479` |
| expressjs/express | `023767fe9872e029271df1418f73401bff20ff40` |

The separately pinned CI sample manifest records its own revisions and hashes.
All fixture sources were scanned as inert data, never built or executed.

## Primary references

- [GitHub's token formats](https://github.blog/engineering/behind-githubs-new-authentication-token-formats/)
  explains classic token prefixes and checksums; shape checks are not validity checks.
- [npm token format](https://github.blog/security/announcing-npms-new-access-token-format/)
  documents the corresponding token-format change.
- [PyTorch serialization notes](https://docs.pytorch.org/docs/main/notes/serialization.html)
  documents the `weights_only` behavior relevant to the deserialization correction.
- [OSV schema](https://ossf.github.io/osv-schema/)
  defines advisory structure and affected ranges.

See [COMPLETION.md](COMPLETION.md) for final test evidence and outstanding release
work. The upgrade is an unreleased working-tree change; nothing has been published.
