# Audit upgrade: 0.4.0 development version

This checkout contains the audit fixes and additional bounded workflows. It is
**unreleased**. Existing v0.3.0 downloads do not contain these changes. Build and
install this reviewed checkout with `cargo install --path . --locked`; the
scanner itself never builds or executes a scanned project.

## Everyday use

```sh
apollyon init .
apollyon scan . --jobs 8 --json
apollyon scan . --only APO007,APO011,APO012 --min-severity high
apollyon scan . --production-only --fail-on high
apollyon scan . --exclude '**/*.min.js' --format markdown --output -
apollyon explain APO011
apollyon scan . --watch
apollyon scan . --fix-dry-run
```

`--only` selects enabled rule IDs. `--min-severity` and `--production-only`
filter displayed findings; production-only also limits failure thresholds to
production paths. Severity filtering does not hide a finding from an explicitly
configured failure threshold. `--include-tests` clears production-only mode.
The default keeps all file classes visible and does not automatically demote
findings in tests: test credentials and test tools can still matter. Classification
is context, not proof of deployment or exposure.

Formats are `text`, `json` (`--json`), `sarif`, `markdown`, `github`, and `gitlab`.
GitLab output uses the Code Quality format. Machine annotations are candidates;
check the process exit code for incomplete scans. `--quiet` gives one text line;
`--stats` retains the standard coverage statistics. Color follows terminal
capability and `NO_COLOR`; use `--color auto|always|never` explicitly.
Snippets remain opt-in and credentials are redacted.

`init [path]` detects a basic language stack and creates configuration without
overwriting files. `--github-action` adds a workflow requiring a trusted
administrator-installed Apollyon binary. `--pre-commit` writes a fragment for
review and merging; it does not activate a hook. `--watch` repeats an inert scan
once per second; `--watch-count N` bounds the number of scans. Stop with Ctrl-C.
Watch cannot be combined with report/case writes, baseline writes, or fixes.

An `apollyon-baseline.json` at the scan root is loaded automatically; an explicit
`--baseline` takes precedence. `--no-auto-baseline` disables discovery. Baselines
use the existing bounded writer-defined schema, not arbitrary JSON.

## Configuration and bounds

Configuration remains a documented single-line TOML subset. Unknown options or
unsupported syntax fail explicitly. It supports these additional keys:

```toml
jobs = 8
max_findings = 10000
max_file_bytes = 2097152
max_total_bytes = 268435456
max_entries = 100000
no_default_ignores = false
ignore_directories = ["local-generated"]
min_severity = "medium"

[[overrides]]
paths = ["tests/**", "**/*_test.go"]
disabled_rules = ["APO010", "APO006"]

[[overrides]]
paths = ["infra/**"]
fail_on = "never"
```

CLI number flags use hyphens instead of underscores. Valid bounds are 1–32 jobs,
1–1,000,000 findings, 1–32 MiB per file, 1–2 GiB aggregate input, and
1–2,000,000 discovered entries. Defaults are shown above, except jobs defaults
to available CPUs capped at eight. Workers merge results in discovery-path order;
serial and parallel results are deterministic for unchanged input. Finding
truncation does not stop later files from being scanned. It is counted and still
makes the result incomplete (exit 3): omitted findings must not be called clean.
Oversized/unreadable files likewise remain explicit coverage failures.

Matching overrides accumulate disabled rules and use the last matching
`fail_on`. They apply after global rule selection and threshold configuration.
`--no-default-ignores` disables the built-in directory list, while explicit
exclusions and `.gitignore` still apply. `--no-gitignore` controls the latter.
Both exclusions and override paths support bounded glob matching, including
`**`, `*`, `?`, and character classes. Snippets never become enabled through config.

## Detection and coverage

The registry has 22 rules. APO013–APO022 add public-prefixed credentials, explicit
debug mode, modeled XSS and SSRF flows, disabled JWT verification, explicit
wildcard/credential CORS configuration, disabled cookie flags, embedded privileged
service-role credentials, modeled NoSQL input, and code-executing agent tools.
These are narrow candidate rules. They do not audit complete authentication,
FireStore/RLS policies, browser context, prompt defenses, or arbitrary frameworks.

JSON and SARIF attach `file_class` (`production`, `test`, `example`, `generated`,
`vendored`). Remote modeled sources yield `tainted`; argv, environment, and
other modeled local input yield `reachable`. Neither label establishes attacker
control or a vulnerability. Traces retain their source and sink and report true
`trace_depth` with `trace_truncated` when intermediate steps are omitted.
Analysis is bounded and mostly intraprocedural; `--interprocedural` adds one
modeled call boundary. General aliasing and control-flow proofs remain outside scope.

SQL modeling uses the first sink argument, supports tracked string construction,
Python f-string / JavaScript template interpolation, and selected raw ORM sinks
including `execute(text(query))`. Bound parameter arguments do not taint a fixed
SQL template. JavaScript child-process imports, aliases, common parameter
shadowing, and reassignment are modeled; this is not whole-program resolution.

Config scanning covers `.env*`, JSON, YAML, TOML, Terraform, INI/config files,
Dockerfile, and shell files for secrets and selected configuration candidates.
It is intentionally lexical. Vue/Svelte `<script>` blocks and Astro frontmatter
are parsed with preserved line positions. Template/style markup is outside this
mode's coverage; component framework semantics are not modeled.

Provider checks use bounded prefixes, lengths, and character sets, with checksum
validation for supported classic GitHub/npm token forms. Formats do not establish
credential validity, and no credential is sent to a provider. JWT text and Twilio
account IDs alone are not secret proof. Explicit `torch.load(weights_only=False)`
is flagged; a blanket `torch.load` rule would be wrong for modern defaults.

## Mechanical fixes

`--fix-dry-run` proposes the supported Python `requests` change
`verify=False` → `verify=True`. `--fix` applies it only after a complete scan,
with a byte-exact `.apollyon.bak` backup and a temporary file replacement.
Existing backup/temp paths are never overwritten. Review TLS compatibility and
rescan after applying. Arbitrary shell rewrites, hash migrations, or SQL
parameterization are not mechanically safe and are not automatically applied.

## Offline dependencies

```sh
apollyon deps .
apollyon deps . --database reviewed-osv-snapshot.json
```

Reads root `package-lock.json` v2/v3, exactly pinned `requirements.txt`,
`Cargo.lock`, and `go.mod`, or one explicit manifest. It does not install packages
or query the network. The embedded snapshot contains **four selected OSV
advisories**, retrieved on 2026-09-08, not the full OSV database. Output identifies
snapshot scope and retrieval date. A zero-match result only concerns that database.
Custom snapshots accept an OSV array or a `records` array (2 MiB, 10,000 records).
Supported numeric range semantics include introduced/fixed/last_affected/limit;
unsupported relevant versions/ranges produce incomplete output. Unpinned Python
requirements and Go replacements require explicit resolution. Nested workspaces,
all package managers, and all ecosystem version schemes are not supported.
Exit codes are 0 complete/no matches, 1 advisory match, 2 invocation/database
error, and 3 incomplete inventory or matching. Maintain a reviewed snapshot from
[OSV's schema](https://ossf.github.io/osv-schema/) and record its source and date.

## Distribution and evidence

Release CI generates five npm packages (wrapper plus four platform binaries)
and a Homebrew formula from checksum-verified release archives. It signs and
attests a separate distribution manifest and retains packages as CI artifacts.
The npm wrapper selects a platform package and forwards arguments without a
shell, postinstall download, or local compilation. crates.io publication is
enabled in Cargo metadata. **No npm/crates.io package or Homebrew tap has been
published by this upgrade.** See [distribution instructions](../distribution/README.md).

The [completion record](audit-2026-09-07/COMPLETION.md) identifies verified checks
and remaining release gates. The [labeled corpus](../benchmarks/audit-corpus.json)
contains one positive and one negative regression per rule; it is too small to
estimate production precision. Pinned upstream samples separately protect the
original APO007/APO012 false-positive patterns. CI fails on label or integrity
regressions. The original seven-case recall fixture remains required.
