# Apollyon repository instructions

Follow the authorization, evidence-gate, and validation rules in `AGENTS.md`.
Use `apollyon scan <path> --format json` for assessments and call every match a
review candidate, not a proven vulnerability. Keep source snippets disabled by
default. Never call an exit-3 incomplete scan clean.

Before completing Rust changes, run formatting, strict Clippy, tests, the
agent/integration validators, and the mixed-project output validator documented
in `CONTRIBUTING.md`.
