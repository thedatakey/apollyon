# Apollyon

**Apollyon** is an open-source, evidence-first cyber-reasoning workbench by
**Tom Koentjes**. The long-term goal is a defensible workflow that connects
discovery, reproduction, remediation, regression testing, and bounded formal
verification without asking an AI model to grade its own work.

> Status: **pre-alpha CLI**. The repository contains a bounded, multi-language
> lexical scanner plus portable coding-agent guidance. It is not yet an
> autonomous cyber-reasoning system, formal verifier, fuzzer, transpiler, or
> confidential-computing platform.

## Scientific boundary

For Turing-complete programs, Rice’s theorem rules out a general decision
procedure for arbitrary non-trivial semantic properties. Apollyon therefore
makes scoped claims: a finding matched a documented rule; a reproducer failed
at a recorded revision; or a property held for a specific harness, assumptions,
and bound. It does not call arbitrary software “unhackable.”

## What works today

The dependency-free Rust CLI scans individual files or recursive projects in
C, C++, C#, Go, Java, Kotlin, JavaScript, TypeScript, PHP, Python, Ruby, Rust,
and Swift. Six review-oriented rules cover C string/memory operations, Rust `unsafe`,
dynamic code execution, operating-system command boundaries, and unsafe
deserialization. Handwritten and AI-generated projects are treated identically;
source provenance is irrelevant.

For a static workspace snapshot, Apollyon rejects or skips discovered symbolic
links, ignores common dependency/build directories, supports additional
exclusions, reports partial scans explicitly, limits per-file and aggregate
input plus result sizes, and emits root-relative finding paths. Do not use this
pre-alpha walker as a security boundary around a tree that an adversary can
mutate concurrently.

## Install and scan

Requires Rust 1.74 or newer:

```sh
cargo install --path .
apollyon scan /path/to/project
apollyon scan /path/to/project --format json
apollyon scan /path/to/project --format sarif --output apollyon.sarif
apollyon scan /path/to/project --exclude generated --exclude test/fixtures
apollyon scan /path/to/project --fail-on high
```

Run `apollyon rules` for the complete rule and language mapping. During source
development, replace `apollyon` with `cargo run --locked --`.
An `--output` path must not already exist: Apollyon refuses to overwrite any
file. This keeps report generation from accidentally replacing source or prior
evidence.

| Format | Intended use |
| --- | --- |
| `text` | Human terminal review |
| `json` | Coding agents and custom automation (`apollyon.findings/v1`) |
| `sarif` | SARIF 2.1.0 consumers and code-scanning ingestion |

Exit codes are stable for automation:

| Code | Meaning |
| ---: | --- |
| 0 | Scan completed and no configured threshold was met |
| 1 | A finding met `--fail-on` |
| 2 | Invalid invocation or output-file creation/write failure |
| 3 | Scan was incomplete; inspect `errors`/warnings |

The scanner is deliberately conservative about its wording. A match is a
`candidate` for review, not proof of exploitability. Snippets are off by
default because they may expose source in logs; enable them only for a trusted
local report with `--include-snippets`.

This is a lexical scanner, not a full parser: generated code, macro expansion,
dynamic imports, string interpolation, and whole-program data flow are outside
the current rule guarantees. `complete` means every discovered, non-excluded,
supported regular file was read within the configured bounds; it does not mean
the project is secure. Static scans never execute target source or build scripts.

## Evidence pipeline

| Status | Required evidence |
| --- | --- |
| `candidate` | Location, bounded rule or reachability rationale |
| `validated` | Safe reproducer or an explicit validation boundary |
| `remediated` | Minimal patch and regression coverage |
| `verified` | Independent post-patch reproduction/test result |
| `inconclusive` | Recorded reason the claim could not be decided |

The shared record format is documented in [`docs/CASE_SCHEMA.md`](docs/CASE_SCHEMA.md).
The machine-readable scan contract is documented in
[`docs/FINDINGS_SCHEMA.md`](docs/FINDINGS_SCHEMA.md).

## Coding-agent integration

The executable does not depend on an AI tool. Any coding program with terminal
access can scan a manually written or generated project. Repository guidance is
kept portable and intentionally thin:

- `AGENTS.md`: canonical workflow for Codex, Cursor, Hermes, GitHub Copilot,
  Windsurf, Cline, OpenCode, and other AGENTS.md-aware clients
- `CLAUDE.md`: Claude Code import of the canonical workflow
- `GEMINI.md`: Gemini CLI import of the canonical workflow
- `.agents/skills/apollyon-scan/SKILL.md`: portable on-demand scan workflow
- `.claude-plugin/plugin.json`: local Claude Code plugin entry point
- `.github/copilot-instructions.md`: Copilot-wide repository guidance
- `.aider.conf.yml`: read-only loading of `AGENTS.md` in Aider

See [`docs/AGENT_INTEGRATIONS.md`](docs/AGENT_INTEGRATIONS.md) for
convention-aligned discovery behavior, setup commands, and platform boundaries.

## Optional specialist team

Project-scoped runtime agents live in [`.codex/agents/`](.codex/agents/). The
active session may use them according to [`AGENTS.md`](AGENTS.md):

- `apollyon-hunter`: read-only discovery and candidate evidence
- `apollyon-verifier`: bounded harnesses and independent validation
- `apollyon-refactor`: minimal remediation with regression tests
- `apollyon-compiler`: threat-modeled build hardening
- `apollyon-orchestrator`: optional second-pass evidence-gate review

These agents are an optional Codex implementation of a portable evidence
workflow; other clients can map the roles to native subagents or run them in
sequence. The human-readable profiles under [`agents/`](agents/) follow the general
[Agency Agents](https://github.com/msitarzewski/agency-agents) persona style,
but they are original Apollyon profiles—not agents installed from its upstream
catalog. Codex executes the TOML files, while the Markdown files document the
intended personas.

Portable request from the repository root:

```text
Use the apollyon-scan workflow to assess this authorized repository. Report
candidate evidence and incomplete coverage. Do not patch unless I ask; if I do,
validate first and independently rerun the original check after the patch.
```

## Local development

Requirements: Rust 1.74 or newer.

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo run -- --help
python3 scripts/validate_agents.py
python3 scripts/validate_integrations.py
python3 scripts/validate_outputs.py target/debug/apollyon
```

GitHub Actions runs these checks plus a locked release build, project-agent
validation, and a Rust 1.74 minimum-version check. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md) before
contributing or reporting a security issue.

## Roadmap

- Parser-backed rules and richer language-specific fixtures
- `.gitignore`-aware traversal and changed-file scanning
- Prebuilt signed binaries for macOS, Linux, and Windows
- Reachability analysis and safe fuzz-harness adapters
- Kani/CBMC/Z3 verification adapters with explicit bounds and tool versions
- Reviewable remediation proposals and regression gates
- Reproducible build metadata and optional platform hardening

Automatic whole-program migration, obfuscation, enclaves, and FHE remain
research tracks. They will not be advertised as working until threat models,
fixtures, benchmarks, and independent validation exist.

## License

MIT. See [`LICENSE`](LICENSE).
