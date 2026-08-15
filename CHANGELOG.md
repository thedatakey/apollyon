# Changelog

All notable changes will be documented here. The project follows semantic
versioning after its first tagged release.

## [Unreleased]

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

### Changed

- Made coding-agent orchestration optional and platform-neutral.
- Expanded CI validation for portable integrations and output contracts.

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
