# Findings output contract

`apollyon scan <path> --format json` emits one compact JSON object on stdout,
unless `--output <file>` is supplied. Consumers must check both the process exit
code and `summary.complete`.

## `apollyon.findings/v1`

```json
{
  "schema": "apollyon.findings/v1",
  "tool": { "name": "apollyon", "version": "0.2.0" },
  "root": "project",
  "summary": {
    "supported_files": 4,
    "scanned_files": 4,
    "skipped_files": 0,
    "skipped_symlinks": 0,
    "excluded_files": 0,
    "excluded_directories": 2,
    "total_bytes": 512,
    "suppressed_errors": 0,
    "complete": true
  },
  "errors": [],
  "findings": [
    {
      "rule_id": "APO004",
      "severity": "high",
      "message": "Dynamic code execution requires review...",
      "path": "src/app.py",
      "line": 4,
      "snippet": null
    }
  ]
}
```

- `root` is a privacy-preserving scan-root label, not an absolute filesystem
  path.
- Finding paths are slash-normalized and relative to the scan root.
- `excluded_files` and `excluded_directories` count supported files omitted by
  explicit `--exclude` rules and directories omitted by built-in or explicit
  rules. They are coverage information, not scan errors.
- `severity` is `info`, `medium`, or `high`.
- `snippet` is `null` unless `--include-snippets` was explicitly enabled.
- `summary.complete` means every discovered, non-excluded, supported regular
  file was read within the scanner's bounds. It is not a security guarantee.
- Any scan, decoding, traversal, lexical, or limit error makes
  `summary.complete` false and produces exit `3`.
- `suppressed_errors` counts errors omitted after the bounded error limit.
- New optional fields may be added within v1. Removing fields or changing their
  meaning requires a new schema discriminator.

## SARIF

`--format sarif` emits SARIF 2.1.0 with stable `ruleId` values, relative
`artifactLocation.uri` values, invocation completeness, and tool notifications
for scan errors. Source snippets remain opt-in. Use `--output` for ingestion
files and parse the same process exit codes documented in the README. SARIF
paths are UTF-8 percent-encoded URI references; JSON paths remain raw relative
paths. The output path must be new because Apollyon never overwrites reports.
