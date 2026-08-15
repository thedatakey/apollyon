# Apollyon

**Apollyon** is an open-source, evidence-first cyber-reasoning workbench by
**Tom Koentjes**. The long-term goal is a defensible workflow that connects
discovery, reproduction, remediation, regression testing, and bounded formal
verification without asking an AI model to grade its own work.

> Status: **pre-alpha foundation**. The repository currently contains a small
> bounded lexical scanner and project-scoped Codex agents. It is not yet an
> autonomous cyber-reasoning system, formal verifier, fuzzer, transpiler, or
> confidential-computing platform.

## Scientific boundary

For Turing-complete programs, Rice’s theorem rules out a general decision
procedure for arbitrary non-trivial semantic properties. Apollyon therefore
makes scoped claims: a finding matched a documented rule; a reproducer failed
at a recorded revision; or a property held for a specific harness, assumptions,
and bound. It does not call arbitrary software “unhackable.”

## What works today

The dependency-free Rust CLI scans regular C, C++, header, and Rust source
files using three review-oriented rules. For a static workspace snapshot, it
rejects or skips discovered symbolic links, reports partial scans explicitly,
limits per-file and aggregate input plus result sizes, and emits root-relative
finding paths. Do not use this pre-alpha walker as a security boundary around a
tree that an adversary can mutate concurrently.

```sh
cargo run -- scan /path/to/source
cargo run -- scan /path/to/source --format json
cargo run -- scan /path/to/source --include-snippets
cargo run -- scan /path/to/source --fail-on high
```

Exit codes are stable for automation:

| Code | Meaning |
| ---: | --- |
| 0 | Scan completed and no configured threshold was met |
| 1 | A finding met `--fail-on` |
| 2 | Invalid command-line usage |
| 3 | Scan was incomplete; inspect `errors`/warnings |

The scanner is deliberately conservative about its wording. A match is a
`candidate` for review, not proof of exploitability. Snippets are off by
default because they may expose source in logs; enable them only for a trusted
local report with `--include-snippets`.

## Evidence pipeline

| Status | Required evidence |
| --- | --- |
| `candidate` | Location, bounded rule or reachability rationale |
| `validated` | Safe reproducer or an explicit validation boundary |
| `remediated` | Minimal patch and regression coverage |
| `verified` | Independent post-patch reproduction/test result |
| `inconclusive` | Recorded reason the claim could not be decided |

The shared record format is documented in [`docs/CASE_SCHEMA.md`](docs/CASE_SCHEMA.md).

## Codex agent team

Project-scoped runtime agents live in [`.codex/agents/`](.codex/agents/). The
primary Codex task orchestrates them according to [`AGENTS.md`](AGENTS.md):

- `apollyon-hunter`: read-only discovery and candidate evidence
- `apollyon-verifier`: bounded harnesses and independent validation
- `apollyon-refactor`: minimal remediation with regression tests
- `apollyon-compiler`: threat-modeled build hardening
- `apollyon-orchestrator`: optional second-pass evidence-gate review

The human-readable profiles under [`agents/`](agents/) follow the general
[Agency Agents](https://github.com/msitarzewski/agency-agents) persona style,
but they are original Apollyon profiles—not agents installed from its upstream
catalog. Codex executes the TOML files, while the Markdown files document the
intended personas.

Example request from the repository root:

```text
Assess this authorized repository. Have apollyon-hunter map candidates and
apollyon-verifier validate the strongest one. Do not patch until validation;
then use apollyon-refactor and have the verifier run a post-patch check.
```

## Local development

Requirements: Rust 1.74 or newer.

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo run -- --help
```

GitHub Actions runs these checks plus a locked release build, project-agent
validation, and a Rust 1.74 minimum-version check. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md) before
contributing or reporting a security issue.

## Roadmap

- Structured rule registry and SARIF output
- Reachability analysis and safe fuzz-harness adapters
- Kani/CBMC/Z3 verification adapters with explicit bounds and tool versions
- Reviewable remediation proposals and regression gates
- Reproducible build metadata and optional platform hardening

Automatic whole-program migration, obfuscation, enclaves, and FHE remain
research tracks. They will not be advertised as working until threat models,
fixtures, benchmarks, and independent validation exist.

## License

MIT. See [`LICENSE`](LICENSE).
