# Public-corpus benchmark

These are measured pre-alpha results, not marketing estimates. They apply to
Apollyon 0.2.0 at scanner commit
`54bedb07e2c10c7ca34c556f418318853fb30610` and the exact corpus revisions in
[`benchmarks/manifest.json`](../benchmarks/manifest.json). The machine-readable
result is [`v0.2.0-phase4.json`](../benchmarks/results/v0.2.0-phase4.json).

## Counting method

`TP`, `FP`, `TN`, and `FN` are computed before the rates. Precision is
`TP/(TP+FP)`, recall is `TP/(TP+FN)`, and false-positive rate is
`FP/(FP+TN)`. An undefined precision is shown as `n/a` rather than zero.

- OWASP uses one labeled `BenchmarkTest` Java file as a unit for each mapped
  CWE/rule pair: APO005/CWE-78, APO008/CWE-327+328, APO009/CWE-330, and
  APO012/CWE-22.
- Juliet uses one documented sink line in each selected `bad` or `good`
  function. The 18 line labels and the selected files are committed in
  `benchmarks/ground-truth.json` and the manifest.
- The curated CVE comparison uses the advisory-linked vulnerable parent and
  fixed commit of PPTAgent CVE-2026-42079 as two units for APO004.

Findings without a compatible label are excluded from the metric and counted
as unscored. This avoids silently treating unrelated review boundaries as
ground truth. It also means these tables do not measure the other rules or
language combinations.

## Measured results

### OWASP Benchmark Java 1.2 labels

All 2,740 Java files scanned through the AST engine with no fallback. The scan
produced 1,162 finding occurrences.

| Rule | TP | FP | TN | FN | Precision | Recall | FPR | Unscored files |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| APO005 | 33 | 30 | 95 | 93 | 52.381% | 26.190% | 24.000% | 0 |
| APO008 | 161 | 0 | 223 | 98 | 100.000% | 62.162% | 0.000% | 0 |
| APO009 | 193 | 0 | 275 | 25 | 100.000% | 88.532% | 0.000% | 0 |
| APO012 | 88 | 76 | 59 | 45 | 53.659% | 66.165% | 56.296% | 557 |

### NIST SARD Juliet C/C++ 1.3 selection

Nine files and all 18 labeled sink lines scanned through the AST engine with no
fallback. The scan produced 25 finding occurrences; 13 were outside the
selected rule/line labels and remain explicitly unscored.

| Rule | TP | FP | TN | FN | Precision | Recall | FPR | Unscored findings |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| APO001 | 3 | 3 | 0 | 0 | 50.000% | 100.000% | 100.000% | 3 |
| APO002 | 3 | 3 | 0 | 0 | 50.000% | 100.000% | 100.000% | 0 |
| APO005 | 0 | 0 | 3 | 3 | n/a | 0.000% | 0.000% | 0 |

The command-injection misses occur because these Juliet cases call a `SYSTEM`
macro rather than a direct `system` function node. APO001/APO002 flag both the
documented bad and good sink calls because they are review-boundary rules and
do not prove buffer adequacy.

### Curated real CVE fixture

Both PPTAgent revisions scanned through the Python AST engine with no fallback.

| Rule | TP | FP | TN | FN | Precision | Recall | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| APO004 | 1 | 1 | 0 | 0 | 50.000% | 100.000% | 100.000% |

The fixed revision still contains `eval`; its extra globals argument removes
the advisory's builtins exposure, but Apollyon's current rule does not model
that argument. This is a measured false positive and a concrete improvement
target. Two APO012 findings in these files were outside the CVE label.

## Reproduce

The fetcher verifies the OWASP label hash, the full official 146 MiB Juliet
archive hash published by NIST, each selected Juliet file hash, and both CVE
source hashes. It downloads source only and never runs corpus code.

```sh
python3 benchmarks/fetch_benchmarks.py /tmp/apollyon-corpora
cargo build --release --locked
python3 benchmarks/run_benchmarks.py \
  --binary target/release/apollyon \
  --corpora /tmp/apollyon-corpora \
  --output-directory /tmp/apollyon-results \
  --scanner-revision 54bedb07e2c10c7ca34c556f418318853fb30610
diff -u benchmarks/results/v0.2.0-phase4.json /tmp/apollyon-results/results.json
```

The published run copied only source and labels into a network-disabled,
unprivileged container with no host mounts, then ran the static scanner. Corpus
applications, builds, tests, package managers, hooks, and dependencies were not
executed.

Sources: [OWASP Benchmark](https://github.com/OWASP-Benchmark/BenchmarkJava),
[NIST SARD Juliet C/C++ 1.3 suite #112](https://samate.nist.gov/SARD/test-suites/112),
and [GitHub advisory GHSA-89g2-xw5c-v95p](https://github.com/advisories/GHSA-89g2-xw5c-v95p).
