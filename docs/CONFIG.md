# Scan configuration and adoption controls

Phase 1 remains lexical and uses no third-party runtime dependencies. All rules
produce review candidates. No source or target code is executed by a static scan.
`--diff` additionally invokes a bounded, read-only Git command.

## Configuration

The CLI reads `apollyon.toml` at the scan directory, or beside an explicitly
scanned file. No ancestor/home-directory config is loaded.

```toml
# Root keys precede the optional severity section.
enabled_rules = ["APO004", "APO007", "APO012"]
disabled_rules = ["APO012"]
excludes = ["generated", "tests/fixtures"]
fail_on = "high"

[severity]
APO004 = "medium"
APO007 = "high"
```

This is a documented TOML subset: one assignment per line, double-quoted
strings (only escaped quote/backslash), single-line string arrays, comments,
and the single `[severity]` table. Unknown keys, unknown rule IDs, duplicates,
other TOML syntax, non-UTF-8, symlinks, or config over 64 KiB are errors (exit 2).

Precedence is built-in defaults, then config, then explicit CLI flags.
`--fail-on never` explicitly overrides config. Repeated `--exclude` values
replace config excludes. `--enable-rule APO004` re-enables a configured disabled
rule and adds it to a configured allowlist. `--disable-rule APO004` wins if both
are provided. `--severity APO004=info` overrides the configured severity.
Without `enabled_rules`, all registered rules are enabled. Disabled matches are
counted, and disabled/suppressed/baselined matches do not trigger `--fail-on`.

The library's `scan_with_settings` accepts explicit `ScanSettings`;
`scan_path` uses default settings and its supplied excludes/snippet flag.
Automatic config loading is a CLI behavior.

## Inline suppression

```python
eval(expression)  # apollyon:ignore[APO004] bounded fixture reviewed
open(path)  # apollyon:ignore reviewed path construction
```

The directive must occur inside a comment recognized by the language's lexer,
including `//`, `#`, or block comments where supported. String and regex text
cannot suppress findings. Scope is the same physical line only. The bracket
form accepts exactly one rule ID without spaces. Malformed bracket directives
suppress nothing. Reasons are optional; they are not treated as instructions.
No next-line behavior is
implemented. Suppressed candidates are included in `suppressed_findings`.

## Baselines

```sh
apollyon scan project --write-baseline baseline.json
apollyon scan project --baseline baseline.json --fail-on high
```

The baseline has a bounded, writer-defined JSON shape:

```json
{"schema":"apollyon.baseline/v1","fingerprints":[]}
```

The reader accepts this key order with whitespace outside strings; arbitrary
JSON extensions or alternate schemas are rejected. Entries are sorted, unique
64-character lowercase hex identifiers. Limits are 2 MiB and 10,000 unique
entries. Read errors or malformed files produce exit 2. A new baseline is
written only for a complete scan and never overwrites an existing file.

The fingerprint is `SHA256(rule_id + NUL + root_relative_path + NUL +
SHA256(original_line_utf8))`, with hex-encoded inner SHA-256. Line numbers and
absolute roots are excluded. An unchanged line retains its fingerprint after
unrelated lines are inserted. Editing its content, comment, or path changes
its identity. Identical duplicate lines in the same file/rule share an identity;
all matching occurrences are counted as baselined. Stale entries simply match
nothing. Baselines contain hashes only, not source or credentials; hashes are
not encryption and files should still be handled as project metadata.

Writing records visible, enabled, unsuppressed findings before applying any
input baseline. This supports deliberate baseline refresh into a new file.

## Changed files

```sh
apollyon scan project --changed-files changed.txt
apollyon scan project --diff HEAD
```

These flags are mutually exclusive. Lists contain one root-relative path per
line; empty lines are ignored. Absolute paths, parent traversal, NULs, colon
paths, and invalid UTF-8 are rejected. Lists are bounded to 2 MiB. Existing
unsupported files/directories and missing selected paths are separately counted.
The latter includes deleted files; it is not a claim that those files were read.
An empty selection can complete with zero scanned files.

Diff mode requires a directory in a Git working tree. It compares tracked
working-tree changes (including staged changes) to the supplied ref, using
`git diff --name-only -z --relative --no-ext-diff --no-textconv`. Untracked files
are not included. Refs beginning with `-` are rejected. Git output is limited
to 2 MiB and execution to 10 seconds; failures produce exit 2. External diff,
text conversion, hooks, and filesystem monitors are disabled for the command.
Git is not invoked in ordinary scan or changed-list mode.

Discovery still accounts for supported files and exclusions before selection.
`unselected_files` counts discovered supported files outside the selection.
Selected paths do not override normal exclusions or symlink checks.

## Gitignore subset

Directory scans respect root and nested `.gitignore` files by default.
`--no-gitignore` disables this behavior. Explicit single-file scans bypass
`.gitignore`, while retaining explicit excludes and file safety checks.

Supported: blank/comment lines, literal patterns, `*` and `?` within one path
component, `!` negation, leading `/` anchoring, and trailing `/` directory rules.
Unanchored basename patterns match at any depth under their ignore file;
patterns containing `/` are relative to that file. Last matching rule wins.
An excluded parent directory is not traversed, so a child negation cannot
re-include it without re-including the parent. Built-in and explicit exclusions
always win.

Not supported: `**`, character classes, backslash escapes, Git global excludes,
`.git/info/exclude`, or index-aware tracked-file exceptions. Unsupported syntax,
invalid UTF-8, unreadable files, and symlinks make the scan incomplete (exit 3),
never silently clean. Each ignore file is limited to 64 KiB, patterns to 1,024
bytes, and the scan to 1,000 loaded rules. Ignored files/directories contribute
to existing exclusion counters.
