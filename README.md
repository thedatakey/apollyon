<h1 align="center">Apollyon — Source Code Security Scanner</h1>

<p align="center"><strong>Find embedded credentials and risky input flows before shipping.</strong></p>

<p align="center">
  Open-source Rust static analysis for human-written and AI-generated code.<br>
  22 bounded review rules · 13 languages · Explicit scan coverage · CI and coding agents
</p>

<p align="center">
  Created by <a href="https://github.com/thedatakey"><strong>Tom Koentjes</strong> (@thedatakey)</a>.
</p>

<p align="center">
  <a href="https://github.com/thedatakey/apollyon/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/thedatakey/apollyon/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/thedatakey/apollyon/releases"><img alt="Release" src="https://img.shields.io/github/v/release/thedatakey/apollyon?include_prereleases&sort=semver&label=release"></a>
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-22d3ee"></a>
  <img alt="Rust 1.85 or newer" src="https://img.shields.io/badge/rust-1.85%2B-f97316">
  <img alt="Public pre-alpha" src="https://img.shields.io/badge/status-public_pre--alpha-f59e0b">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#see-it-work">See a real scan</a> ·
  <a href="https://github.com/thedatakey/apollyon/releases/tag/v0.3.0">Download v0.3.0</a> ·
  <a href="docs/AGENT_INTEGRATIONS.md">Coding-agent setup</a> ·
  <a href="#current-capabilities">Supported rules</a>
</p>

<p align="center">
  <img src="docs/assets/apollyon-social-preview.png" alt="Apollyon — evidence-first source code security scanner" width="80%">
</p>

Apollyon is an evidence-first static analysis CLI written in Rust. It flags
bounded security-review candidates for embedded credentials, unsafe input flows,
SQL, command execution, TLS, memory operations, and selected web/configuration
patterns across 13 languages, without executing the target project. It works on ordinary local
source trees, whether the code was written by a person or generated with AI.

Every report records supported, scanned, skipped, and excluded counts, along
with errors and whether the scan completed. Use terminal text for local review,
versioned JSON v2 with engine, confidence, and source-to-sink traces for coding agents and automation, or SARIF 2.1.0 for CI and
GitHub code scanning.

**Status: public pre-alpha; this checkout is the unreleased 0.4.0 development version.**
The v0.3.0 downloads below do not include the audit upgrade. This checkout implements 22 bounded
review rules with AST validation, bounded taint traces, and an opt-in case
workflow for one Python eval boundary. Findings require human validation; a complete scan is not proof
that a project is secure.

## What changed in the audit follow-up

- **Broader bounded coverage:** 22 rules, selected SQL/ORM flows, provider credential
  checks, config files, and scripts in Vue, Svelte, and Astro components.
- **Faster scans with explicit limits:** deterministic parallel workers, configurable
  resource bounds, and incomplete status when coverage or output is truncated.
- **Daily workflows:** rule explanations, filters, baselines, configuration setup,
  watch mode, and a narrow opt-in Python TLS fix with backups.
- **Offline dependency checks:** supported lockfiles matched against a small,
  declared advisory snapshot; this is not a comprehensive vulnerability database.

The audit fixes passed **114 Rust, 6 Python, and 6 Node tests** locally.
[Cross-platform CI](https://github.com/thedatakey/apollyon/actions/runs/34492038254)
passed Linux, macOS, Windows, Rust 1.85 compatibility, and the composite action.
The [completion record](docs/audit-2026-09-07/COMPLETION.md) separates measured
results, analysis limits, and the remaining release/publication gates.

## Quick start

Install the development version from `main` with Rust 1.85 or newer:

```sh
cargo install --locked --git https://github.com/thedatakey/apollyon \
  --branch main apollyon
apollyon scan . --production-only --fail-on high
apollyon explain APO011
```

The [complete CLI reference](docs/CLI.txt) is also the exact `--help` source.
The [audit upgrade guide](docs/AUDIT_UPGRADE.md) documents parallel scanning,
filters, config/component coverage, init/watch/fix, offline dependency checks,
and the unpublished npm/Homebrew packages. Exact results and remaining gates
are recorded in the [completion report](docs/audit-2026-09-07/COMPLETION.md).


### Install the older v0.3.0 prerelease

For the tagged version without the audit upgrade (Rust 1.85 or newer):

```sh
cargo install --locked --git https://github.com/thedatakey/apollyon \
  --tag v0.3.0 apollyon
```

### Download a v0.3.0 prebuilt binary

The v0.3.0 prerelease provides these archives:

| Platform | Asset |
| --- | --- |
| Linux x86-64 | [`apollyon-v0.3.0-x86_64-unknown-linux-musl.tar.gz`](https://github.com/thedatakey/apollyon/releases/download/v0.3.0/apollyon-v0.3.0-x86_64-unknown-linux-musl.tar.gz) |
| macOS Apple Silicon | [`apollyon-v0.3.0-aarch64-apple-darwin.tar.gz`](https://github.com/thedatakey/apollyon/releases/download/v0.3.0/apollyon-v0.3.0-aarch64-apple-darwin.tar.gz) |
| macOS Intel | [`apollyon-v0.3.0-x86_64-apple-darwin.tar.gz`](https://github.com/thedatakey/apollyon/releases/download/v0.3.0/apollyon-v0.3.0-x86_64-apple-darwin.tar.gz) |
| Windows x86-64 | [`apollyon-v0.3.0-x86_64-pc-windows-msvc.zip`](https://github.com/thedatakey/apollyon/releases/download/v0.3.0/apollyon-v0.3.0-x86_64-pc-windows-msvc.zip) |

Verify the archive against the published
[`SHA256SUMS`](https://github.com/thedatakey/apollyon/releases/download/v0.3.0/SHA256SUMS),
its keyless Sigstore bundle, and GitHub SLSA build-provenance attestation before use. See the
[installation guide](docs/INSTALL.md) for exact verification commands and
platform notes.

### Scan a project

```sh
apollyon scan /path/to/project
apollyon scan /path/to/project --format json
apollyon scan /path/to/project --format sarif --output apollyon.sarif
apollyon scan /path/to/project --exclude generated --exclude test/fixtures
apollyon scan /path/to/project --fail-on high
apollyon rules
```

An `--output` path must not already exist. Apollyon refuses to overwrite source,
previous reports, or any other file.

## See it work

Scanning the checked-in mixed-language fixture produces review candidates and
an explicit coverage summary:

```text
$ apollyon scan tests/fixtures/manual-project --exclude generated
Apollyon: scan complete — 5 findings (4 high, 1 medium, 0 info).
Findings require review; scan completion is not a security verdict.

[HIGH] APO006 src/Service.java:5 (ast/candidate)
  Deserialization API may construct attacker-controlled objects; require a safe format, trusted input, or an explicit allowlist.
  Next: apollyon explain APO006
[HIGH] APO004 src/app.py:5 (ast/candidate)
  Dynamic code execution requires review of whether code or input can be influenced by an attacker.
  Next: apollyon explain APO004
[HIGH] APO006 src/app.py:9 (ast/candidate)
  Deserialization API may construct attacker-controlled objects; require a safe format, trusted input, or an explicit allowlist.
  Next: apollyon explain APO006
[HIGH] APO001 src/legacy.c:4 (ast/candidate)
  Unbounded C string operation may permit memory corruption; use a length-aware API and verify destination bounds.
  Next: apollyon explain APO001
[MEDIUM] APO005 src/runner.ts:4 (ast/candidate)
  Operating-system command execution requires review of argument separation, shell use, and untrusted input.
  Next: apollyon explain APO005

5 finding(s); 4/4 supported file(s) scanned; 530 byte(s) read; 0 symlink(s) skipped; 0 file(s) and 2 directories excluded; complete: true.
5 new; 0 baselined; 0 suppressed; 0 disabled; 5 total candidate(s); 0 unselected file(s); 0 missing selected path(s); 0 unsupported selected path(s); 4 AST file(s); 0 lexical fallback file(s).
```

The summary is part of the evidence. `complete: true` describes bounded scan
completion; it is never a security verdict.

If this evidence-first approach is useful, click GitHub's **Star** button to
bookmark Apollyon and help other developers discover it. Use
**Watch → Custom → Releases** when you want release notifications.

Trying the pre-alpha? [Report a reproducible bug](https://github.com/thedatakey/apollyon/issues/new?template=bug_report.md)
or [request a bounded rule or language](https://github.com/thedatakey/apollyon/issues/new?template=feature_request.md).
False positives, missing language behavior, and coding-agent integration
feedback are especially useful.

## Why Apollyon?

Apollyon is built for developers reviewing human-written or AI-assisted pull
requests, AppSec and DevSecOps teams that need auditable local evidence, and
coding-agent workflows that must distinguish "no matches" from "scan
incomplete."

- **Evidence before verdicts:** every lexical match remains a review candidate.
- **Explicit coverage:** reports scanned, skipped, excluded, and incomplete work.
- **Provenance-neutral:** evaluates handwritten and AI-generated source equally.
- **Automation-ready:** stable exit codes plus JSON and SARIF 2.1.0.
- **Agent-ready:** standalone CLI plus checked-in guidance for Codex, Claude Code,
  Cursor, Gemini CLI, Hermes, Copilot, OpenCode, Aider, and other
  terminal-capable environments.
- **No target execution:** scans source without running project code, builds,
  hooks, package managers, or dependencies.
- **Pinned parser stack:** tree-sitter and all language grammars use exact
  versions recorded in `Cargo.lock`.

## Current capabilities

The table below describes the original twelve families. APO013–APO022 add
public credential exposure, debug mode, XSS, SSRF, JWT, CORS, cookies, privileged
service credentials, NoSQL, and agent tool candidates. See [all rules](docs/RULES.md).

Regression measurements cover 22 labeled positive/negative pairs and pinned
upstream negative samples. These small tests do not establish real-world
precision; [measurement output](docs/audit-2026-09-07/corpus-results.json)
records per-rule counts when the gate has passed.


Apollyon recognizes source files across 13 languages: C, C++, C#, Go, Java,
Kotlin, JavaScript, TypeScript, PHP, Python, Ruby, Rust, and Swift. Rule coverage
is intentionally narrow and language-specific; recognition does not imply broad
semantic coverage. Run `apollyon rules` for the executable rule registry.

| Rule | Severity | Review boundary | Languages |
| --- | --- | --- | --- |
| `APO001` | high | Unbounded C string operation | C, C++ |
| `APO002` | info | Manual memory-copy boundary | C, C++ |
| `APO003` | medium | Rust `unsafe` boundary | Rust |
| `APO004` | high | Dynamic code execution | JavaScript, TypeScript, Python, PHP, Ruby |
| `APO005` | medium | Operating-system command execution | C, C++, C#, Go, Java, Kotlin, JavaScript, TypeScript, PHP, Python, Ruby, Rust, Swift |
| `APO006` | high | Unsafe deserialization boundary | C#, Java, Kotlin, PHP, Python, Ruby |
| `APO007` | high | Embedded credential material | All supported languages |
| `APO008` | medium | Weak cryptographic primitive | All supported languages |
| `APO009` | info | Non-cryptographic randomness | C, C++, Java, Kotlin, JavaScript, TypeScript, PHP, Python |
| `APO010` | high | Disabled TLS verification | C, C++, Go, Java, Kotlin, JavaScript, TypeScript, PHP, Python |
| `APO011` | medium | Dynamically assembled SQL | All supported languages |
| `APO012` | medium | Modeled input in filesystem path | All supported languages |

For a static workspace snapshot, Apollyon skips symbolic links, ignores common
dependency/build directories, supports explicit file and directory exclusions,
uses bounded traversal/input/output limits, emits root-relative paths, and
makes decoding, lexical, traversal, and limit failures explicit.

See [rule boundaries](docs/RULES.md) for exact patterns, language coverage, and
known limits.

For adoption controls:

```sh
apollyon scan project --write-baseline baseline.json
apollyon scan project --baseline baseline.json --fail-on high
apollyon scan project --diff HEAD
apollyon scan project --changed-files changed.txt
apollyon scan project --no-gitignore --disable-rule APO009
```

Inline comment suppressions, bounded `.gitignore` handling, and optional
`apollyon.toml` configuration are documented in [CONFIG.md](docs/CONFIG.md).
Every hidden candidate remains counted as suppressed, disabled, or baselined.

### Regression evidence

All 22 rules passed their labeled positive/negative pairs. Each rule has only
one positive and one negative synthetic case, so these checks do not establish
production precision or recall. CI also checks pinned upstream negative samples.
See the [per-rule results](docs/audit-2026-09-07/corpus-results.json) and
[full audit verification record](docs/audit-2026-09-07/COMPLETION.md) for counts,
original-corpus reruns, performance measurements, and limitations.

## Authorized evidence cases

Static case creation is opt-in and requires an explicit authorization marker:

```sh
apollyon scan project --format json --output findings.json \
  --cases-dir case-output --authorized \
  --repository owner/project --revision commit-sha
```

Only tainted findings create candidate cases. Static scanning still does not
execute target code. The first dynamic adapter is limited to a function-local
Python `eval` case and runs only through the documented disposable Docker
sandbox:

```sh
docker build --tag apollyon-phase3-tools:1 docker/phase3-tools
python3 scripts/run_case_sandbox.py \
  --case case-output/APO-....json --source-root project \
  --output verified-case.json --adapter python-eval \
  --propose-fix --formal-z3 --fuzz-seconds 1
```

It returns a proposed diff and bounded evidence; it does not modify the host
project. See the [sandbox threat model](docs/SANDBOX.md) and
[case contract](docs/CASE_SCHEMA.md).

## Automation contract

| Format | Intended use |
| --- | --- |
| `text` | Human terminal review |
| `json` | Coding agents and custom automation (`apollyon.findings/v2`) |
| `sarif` | SARIF 2.1.0 consumers and code-scanning ingestion |

| Exit | Meaning |
| ---: | --- |
| 0 | Scan completed and no configured threshold was met |
| 1 | A finding met `--fail-on` |
| 2 | Invalid invocation or output-file creation/write failure |
| 3 | Scan was incomplete; inspect `errors` or terminal warnings |

Consumers must inspect both the exit code and structured `summary.complete`.
Exit `0` can still include candidates when no `--fail-on` threshold was set.
The complete schema is documented in [the findings contract](docs/FINDINGS_SCHEMA.md).

## GitHub Action and editor adoption

The composite Action builds the exact referenced Apollyon revision, supports a
baseline and severity threshold, emits SARIF, and can upload it to GitHub code
scanning:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
    with:
      persist-credentials: false
  - uses: thedatakey/apollyon/.github/actions/apollyon@v0.3.0
    with:
      path: .
      fail-on: high
      baseline: apollyon-baseline.json
```

For pre-commit, add the released hook to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/thedatakey/apollyon
    rev: v0.3.0
    hooks:
      - id: apollyon
```

Then install it in one line:

```sh
pre-commit install && pre-commit run apollyon --all-files
```

The source VS Code extension in [`vscode-apollyon`](vscode-apollyon) renders an
`apollyon.sarif` report as inline diagnostics. The full measured public-corpus
results and exact reproduction commands are in
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

## Coding-agent integration

The executable does not depend on an AI tool. Portable guidance layers the same
evidence contract onto major coding environments:

- `AGENTS.md` is the canonical client-neutral workflow.
- `CLAUDE.md` and `.claude-plugin/plugin.json` expose it to Claude Code.
- `GEMINI.md` exposes it to Gemini CLI.
- `.agents/skills/apollyon-scan/SKILL.md` provides a reusable Agent Skill.
- `.github/copilot-instructions.md` and `.aider.conf.yml` cover Copilot and Aider.
- `.codex/agents/` contains optional specialist roles for Codex projects.

Integration files are structurally validated against documented conventions.
Runtime behavior in every third-party client is not claimed. See the
[integration guide](docs/AGENT_INTEGRATIONS.md) for global installation paths,
Claude's namespaced command, Hermes usage, and platform-specific boundaries.

## Frequently asked questions

### Can Apollyon scan manually written projects?

Yes. Apollyon is provenance-neutral: it scans ordinary human-written source and
AI-generated source with the same bounded rules. No coding agent is required.

### Does Apollyon execute the project it scans?

No. Static scanning does not run target builds, tests, hooks, package managers,
or dependencies. Treat any separately authorized dynamic verification as a
different, isolated workflow.

### Does it replace CodeQL, Semgrep, or expert security review?

No. Apollyon is a bounded pre-alpha AST-assisted scanner and should complement mature
analysis tools and human review. Its current advantage is an explicit,
machine-readable account of scan coverage and incomplete work.

### Can coding agents use it?

Yes. The CLI works from any terminal-capable environment, and the repository
includes documented workflows for Codex, Claude Code, Cursor, Gemini CLI,
Hermes, Copilot, OpenCode, and Aider. See the
[coding-agent integration guide](docs/AGENT_INTEGRATIONS.md).

## Evidence pipeline

| Status | Required evidence |
| --- | --- |
| `candidate` | Location plus bounded rule or reachability rationale |
| `validated` | Safe reproducer or an explicit validation boundary |
| `remediated` | Minimal patch and regression coverage |
| `verified` | Independent post-patch reproduction/test result |
| `inconclusive` | Recorded reason the claim could not be decided |

Durable records follow the [case schema](docs/CASE_SCHEMA.md). Target code,
comments, diagnostics, and scan output remain untrusted data—not instructions
or authorization to execute code.

## Limits and scientific boundary

Apollyon uses tree-sitter parsing and bounded same-file taint models; it is not a whole-program analyzer. Macro expansion, dynamic dispatch/imports, reflection, complex aliasing, framework behavior, and whole-program data flow remain outside current guarantees. Files that fail to parse use an explicitly counted lexical fallback. Public-corpus measurements cover only the rule/language pairs and fixed revisions documented in [the benchmark report](docs/BENCHMARKS.md); they do not support a general accuracy claim.

For Turing-complete programs, Rice's theorem rules out a general decision
procedure for arbitrary non-trivial semantic properties. Apollyon therefore
makes scoped claims: a documented rule matched, a bounded reproducer failed, or
a property held for a specific harness, assumptions, and bound. It never calls
arbitrary software "unhackable."

Do not use the pre-alpha filesystem walker as a security boundary around a tree
that an adversary can mutate concurrently. Static scanning never requires
running target builds, tests, hooks, package managers, or dependencies.

## Development and contributing

The scanner is now a library with a thin CLI entry point. See
[the architecture](docs/ARCHITECTURE.md) for module responsibilities and the
scan pipeline, and [the phased upgrade plan](docs/UPGRADE_PLAN.md) for the
implementation record. Findings v2 is the current structured contract;
committed golden tests compare exact CLI output bytes.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo build --release --locked
cargo +1.85.0 check --locked
python3 scripts/validate_agents.py
python3 scripts/validate_integrations.py
python3 scripts/validate_outputs.py target/debug/apollyon
python3 scripts/validate_release.py
python3 scripts/validate_phase4.py
python3 -m unittest discover -s benchmarks -p 'test_*.py'
python3 tests/test_release_packaging.py
node --test vscode-apollyon/test/*.test.js
```

GitHub Actions runs the full gate on Linux and portable test builds on macOS
and Windows. Tagged releases additionally validate version identity, build four
native archives twice, compare binary digests, smoke-test each executable,
publish a signed SHA-256 manifest, and attach signed SLSA build provenance.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and the
[code of conduct](CODE_OF_CONDUCT.md) before contributing or reporting an issue.
Maintainer release steps are documented in [docs/RELEASING.md](docs/RELEASING.md).

## Roadmap

- Broader AST queries and framework-specific taint models
- Broader Git ignore syntax and richer changed-file analysis
- Platform notarization and package-manager distribution
- More evidence adapters beyond the current bounded Python eval workflow
- Kani or CBMC adapters for memory properties
- Broader public-corpus coverage across rules and languages

Automatic whole-program migration, obfuscation, enclaves, and FHE remain
research tracks. They will not be advertised as working until threat models,
fixtures, benchmarks, and independent validation exist.

## Author and license

Apollyon was created and is maintained by
**[Tom Koentjes](https://github.com/thedatakey)** (`@thedatakey`). Copyright
© 2026 Tom Koentjes. Released under the MIT License; see [LICENSE](LICENSE).
