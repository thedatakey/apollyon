# Architecture

Apollyon is a zero-dependency Rust library and CLI. Phase 0 extracts the existing
implementation without adding detection behavior or changing findings v1,
SARIF, text output, CLI options, or exit codes. The baseline is commit
`d1dc52e6a200d35c2dc974bfd4e1234276313681`, including the C# proximity fix and
machine-readable scope note.

## Module responsibilities

| Module | Responsibility |
| --- | --- |
| `src/main.rs` | Collect arguments and exit with the library's status. |
| `src/lib.rs` | Dispatch commands and expose the library entry points. |
| `src/cli.rs` | Argument parsing, command/options types, usage, exclude normalization, create-new output files. |
| `src/lexer.rs` | Extension-to-language mapping; stateful comment, string, raw-string, lifetime, and regex handling. |
| `src/scanner.rs` | Discovery, exclusions, bounded reads, coverage, per-file scan orchestration, ordering. |
| `src/report.rs` | `Finding`, `ScanReport`, and bounded report errors. |
| `src/rules/mod.rs` | Six-rule registry, metadata, severities, and registry lookup. |
| `src/rules/patterns.rs` | Shared lexical token, call, and Ruby command matching. |
| `src/rules/memory.rs` | APO001–APO003: C memory operations and Rust `unsafe`. |
| `src/rules/exec.rs` | APO004–APO005: dynamic code and operating-system commands. |
| `src/rules/deserialization.rs` | APO006 and the 20-line C# formatter proximity window. |
| `src/display.rs` | Bounded snippets and escaping unsafe terminal characters. |
| `src/render/` | Text/rule listing, JSON, and SARIF serializers; shared scope note. |

Unit tests live with their modules. Existing language/rule end-to-end tests
remain in `scanner.rs`, where they exercise sanitizing and matching together.
`tests/golden_output.rs` invokes the binary and exercises the public library API.

## Scan pipeline

1. Parse arguments and normalize relative exclusions. Snippets remain opt-in.
2. Discover supported regular files. Reject a symlink root; skip discovered
   symlinks and built-in/excluded directories. Sort discovered paths.
3. Resolve each path within the root, inspect/open it, compare device/inode on
   Unix, and read within the per-file bound. Check resolved paths again after
   reading. These checks do not secure a concurrently adversarial filesystem.
4. Account for bytes and decoding failures. Lossy UTF-8 is explicitly incomplete.
5. Sanitize each line with per-file lexical state. Run memory, execution, then
   deserialization matchers in the original rule order. C# formatter state
   remains local to each file. Apply finding budgets before creating findings.
6. Record incomplete lexical state or resource exhaustion. Sort findings by
   relative path and line, preserving rule order on the same line.
7. Render the report. Output files are create-new only and private on Unix.
   Exit precedence remains output error (2), incomplete scan (3), configured
   finding threshold (1), then complete (0).

No scanned source is executed. Matching remains lexical and produces review
candidates, not validated vulnerabilities.

## Existing resource bounds

| Resource | Bound |
| --- | ---: |
| Source file | 2 MiB |
| Aggregate input | 256 MiB |
| Discovered entries | 100,000 |
| Findings | 10,000 |
| Recorded errors | 1,000, with overflow counted |
| Snippet | 180 source characters before display escaping |

The scanner owns input/discovery limits; the display module owns snippet limits.
Coverage and incompleteness semantics are unchanged. See
[FINDINGS_SCHEMA.md](FINDINGS_SCHEMA.md) for the output contract.

## Library surface

The crate exports `scan_path`, `Finding`, `ScanReport`, `Severity`,
`render_text`, `render_json`, `render_sarif`, `render_rules`, and `run`.
Internal modules and matching helpers are not public API.

`scan_path(&Path, include_snippets, &[String])` returns a report; callers must
inspect `complete` and `errors`. It performs bounded filesystem reads but does
not write output. Renderers return strings; JSON and SARIF have no trailing
newline until the CLI emits them. `run(&[String])` performs CLI I/O and returns
an exit code instead of terminating its caller. The library API is pre-alpha.

## Compatibility checks

Nine golden files were captured from the original binary before extraction:
three formats each for default scanning, excluded generated source, and
explicit snippets. Tests require exact stdout bytes, empty stderr, and exit 0.
Additional tests cover exit codes 1/2/3 and library rendering parity. All 35
pre-existing tests retain their inputs and assertions.

Fixtures and snapshots use LF on every platform, enforced by `.gitattributes`;
this matters for byte counts. Snapshots are never automatically regenerated.
See [the snapshot provenance](../tests/fixtures/golden/README.md). The test
corpus bounds the compatibility evidence; it cannot prove equivalence for all
possible inputs.
