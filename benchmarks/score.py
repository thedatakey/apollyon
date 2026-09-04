#!/usr/bin/env python3
"""Score snippet-free Apollyon reports against pinned public labels."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent
OWASP_MAPPING = {"APO005": {78}, "APO008": {327, 328}, "APO009": {330}, "APO012": {22}}


def metric(rule_id: str, language: str, labels: list[tuple[bool, bool]], unscored: int = 0) -> dict:
    tp = sum(actual and predicted for actual, predicted in labels)
    fp = sum(not actual and predicted for actual, predicted in labels)
    tn = sum(not actual and not predicted for actual, predicted in labels)
    fn = sum(actual and not predicted for actual, predicted in labels)
    ratio = lambda top, bottom: round(top / bottom, 6) if bottom else None
    return {
        "rule_id": rule_id,
        "language": language,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "unscored_findings": unscored,
    }


def read_report(path: Path) -> dict:
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("schema") != "apollyon.findings/v2" or report.get("summary", {}).get("complete") is not True:
        raise ValueError(f"incomplete or unexpected report: {path}")
    if any(finding.get("snippet") is not None for finding in report["findings"]):
        raise ValueError(f"benchmark report contains source snippets: {path}")
    return report


def owasp_metrics(report: dict, labels_path: Path) -> list[dict]:
    labels = {}
    with labels_path.open(newline="", encoding="utf-8") as source:
        for row in csv.reader(line for line in source if not line.startswith("#")):
            labels[row[0]] = (row[2] == "true", int(row[3]))
    predicted: dict[str, set[str]] = {}
    for finding in report["findings"]:
        match = re.search(r"BenchmarkTest\d+", finding["path"])
        if match:
            predicted.setdefault(finding["rule_id"], set()).add(match.group())
    results = []
    for rule_id, cwes in OWASP_MAPPING.items():
        units = {name: positive for name, (positive, cwe) in labels.items() if cwe in cwes}
        rule_predictions = predicted.get(rule_id, set())
        results.append(
            metric(
                rule_id,
                "Java",
                [(positive, name in rule_predictions) for name, positive in sorted(units.items())],
                len(rule_predictions - set(units)),
            )
        )
    return results


def exact_metrics(report: dict, truth: list[dict]) -> list[dict]:
    predicted = {(item["rule_id"], item["path"], item["line"]) for item in report["findings"]}
    grouped: dict[tuple[str, str], list[tuple[bool, bool]]] = {}
    scored = set()
    for item in truth:
        key = (item["rule_id"], item["path"], item["line"])
        scored.add(key)
        grouped.setdefault((item["rule_id"], item["language"]), []).append((item["positive"], key in predicted))
    results = []
    for (rule_id, language), labels in sorted(grouped.items()):
        unscored = sum(1 for item in predicted if item[0] == rule_id and item not in scored)
        results.append(metric(rule_id, language, labels, unscored))
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--owasp-report", required=True, type=Path)
    parser.add_argument("--owasp-labels", required=True, type=Path)
    parser.add_argument("--juliet-report", required=True, type=Path)
    parser.add_argument("--cve-report", required=True, type=Path)
    parser.add_argument("--scanner-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("--output must not exist")
    reports = {name: read_report(path) for name, path in {
        "owasp": args.owasp_report, "juliet": args.juliet_report, "cve": args.cve_report
    }.items()}
    truth = json.loads((ROOT / "ground-truth.json").read_text(encoding="utf-8"))
    result = {
        "schema": "apollyon.benchmarks/results/v1",
        "scanner_version": reports["owasp"]["tool"]["version"],
        "scanner_revision": args.scanner_revision,
        "counting_unit": {
            "owasp": "one labeled BenchmarkTest file per mapped rule",
            "juliet": "one labeled sink line in selected bad/good functions",
            "cve": "one advisory-linked affected/fixed source revision",
        },
        "corpora": {
            "owasp": {"coverage": reports["owasp"]["summary"], "metrics": owasp_metrics(reports["owasp"], args.owasp_labels)},
            "juliet": {"coverage": reports["juliet"]["summary"], "metrics": exact_metrics(reports["juliet"], truth["juliet"])},
            "cve": {"coverage": reports["cve"]["summary"], "metrics": exact_metrics(reports["cve"], truth["cve"])},
        },
        "input_report_sha256": {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in {
                "owasp": args.owasp_report, "juliet": args.juliet_report, "cve": args.cve_report
            }.items()
        },
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
