# Changelog

All notable changes will be documented here. The project follows semantic
versioning after its first tagged release.

## [Unreleased]

### Added

- Phase 2 tree-sitter parsing with exactly pinned grammars for all 13 supported
  languages, AST validation for lexical candidates, and explicitly counted
  lexical fallback.
- Bounded intraprocedural taint evidence and opt-in one-boundary same-file
  interprocedural analysis with ordered source-to-sink traces.
- Findings schema v2 with required `engine`, `confidence`, and `trace` fields.

- Phase 1 lexical rules APO007–APO012 for secret, crypto, randomness, TLS, SQL,
  and filesystem review boundaries, with positive/negative fixtures.
- Same-line comment suppressions, SHA-256 baselines, changed-file lists and
  bounded Git diffs, bounded nested gitignore handling, and configuration.
- Explicit counts for suppressed, disabled, baselined, new, and total candidates,
  plus selected-file coverage. Secret candidate lines remain redacted.

- Nine exact CLI output snapshots for text, JSON, and SARIF, covering default
  scanning, exclusions, and explicitly enabled snippets; integration checks
  for exit codes and library/CLI rendering parity.
- Architecture documentation and a phase-by-phase upgrade implementation plan.
- `scope` field in JSON and SARIF (`tool.driver.properties.scope`) output
  carrying a fixed reminder that findings reflect a bounded lexical rule
  set and that zero findings is not a security guarantee.

### Fixed

- `APO006` (unsafe deserialization) for C# no longer treats an unsafe
  formatter constructor as unbounded evidence for the rest of the file; a
  `Deserialize` call now only counts as a candidate within
  `CSHARP_FORMATTER_PROXIMITY_LINES` (20) lines of the constructor.

### Changed

- Minimum supported Rust version is 1.85 after adding the parser dependency set.
- Phase 2 golden snapshots intentionally move to findings v2 and add engine,
  confidence, trace, and parser-coverage fields; Phase 1 content is unchanged.

- Phase 1 golden snapshots intentionally add the new rule registry, stable
  finding fingerprints, and control/selection counters. Existing manual-project
  findings and coverage remain unchanged; findings v1 is retained.

- Internal restructure into a library crate; no behavior change. The binary
  delegates to the library, with cohesive CLI, lexer, scanner, report,
  rule-family, display, and rendering modules. All 35 original tests are
  preserved as module unit tests; no runtime dependencies were added.
- Made creator attribution prominent in the README and public repository
  metadata.
- Improved GitHub discovery and onboarding with clearer product copy, direct
  release downloads, user-focused FAQs, and feedback calls to action.

## [0.2.0] - 2026-08-15

### Added

- Portable `AGENTS.md` workflow with Claude Code, Cursor, Hermes, Gemini CLI,
  GitHub Copilot, Windsurf, Cline, OpenCode, and Aider integration surfaces.
- Repository-scoped `apollyon-scan` Agent Skill and Claude Code plugin manifest.
- C#, Go, Java, Kotlin, JavaScript, TypeScript, PHP, Python, Ruby, and Swift
  discovery alongside the existing C, C++, header, and Rust support.
- Dynamic-execution, operating-system-command, and unsafe-deserialization rules.
- SARIF 2.1.0 output, safe create-new report files, repeated path exclusions,
  expanded default dependency/build exclusions, and a `rules` command.
- Machine-readable excluded-file/directory coverage accounting and stable
  incomplete-scan semantics for empty or unsupported targets.
- Mixed handwritten-project fixtures and machine-output contract validation.
- Public GitHub launch materials, installation and checksum-verification guide,
  social preview artwork, citation metadata, and security-report routing.
- Tag-gated release automation for Linux x86-64, macOS Apple Silicon, macOS
  Intel, and Windows x86-64 archives with SHA-256 checksums and GitHub build
  attestations.

### Changed

- Made coding-agent orchestration optional and platform-neutral.
- Expanded CI validation for portable integrations and output contracts.
- Reworked the README around the current CLI, honest pre-alpha positioning,
  copy-paste installation, real output, narrow rule coverage, and download UX.
- Disabled accidental crates.io publication until a deliberate package release
  process exists.

## [0.1.0] - 2026-08-15

### Added

- Pre-alpha Rust CLI with bounded C/C++ and Rust source checks
- Text and structured JSON output
- Explicit incomplete-scan reporting and CI-oriented exit codes
- Project-scoped Codex agent team and shared case schema
- GitHub Actions, contribution, conduct, and security policies

### Security

- Discovered symbolic links are rejected or skipped for static workspace scans
- Per-file, aggregate-input, traversal, error, snippet, and finding limits cap
  ordinary resource use; concurrently mutable trees remain out of scope
