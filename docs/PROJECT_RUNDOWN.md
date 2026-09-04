# Project rundown — Apollyon

Source reviewed: `Apollyon AI Code Protector Project.md` supplied by Tom Koentjes on 2026-08-15.

## Product intent

Build a free, open-source cyber-reasoning system that discovers, validates, and helps remediate security defects with a multi-agent workflow.

## Decisions adopted for the initial build

1. Make bounded, evidence-backed claims instead of claims of absolute invulnerability.
2. Require an independently reproducible validation artifact before a patch is approved.
3. Start with source-level findings and structured output; add fuzzing, formal tools, and remediation adapters incrementally.
4. Keep all code transformations reviewable and opt-in.
5. Maintain a defensive-only scope.

## Explicitly deferred

- Automatic C/C++-to-Rust migration
- Kani and CBMC execution adapters
- Enclave/FHE integrations
- Any automatic obfuscation pipeline

These need dedicated threat models, reproducible test fixtures, and acceptance criteria before implementation. Phase 3 now includes a narrow Z3 syntax-property adapter; it does not replace future memory-property work.
