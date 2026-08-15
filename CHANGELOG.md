# Changelog

All notable changes will be documented here. The project follows semantic
versioning after its first tagged release.

## [Unreleased]

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
