#!/usr/bin/env python3
"""Exercise Apollyon's agent-facing JSON, SARIF, and exit-code contracts."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "manual-project"
EXPECTED_RULES = {"APO001", "APO004", "APO005", "APO006"}


def invoke(binary: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def main() -> int:
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "target" / "debug" / "apollyon"
    if not binary.is_absolute():
        binary = (ROOT / binary).resolve()
    if not binary.is_file():
        print(f"error: Apollyon binary not found: {binary}", file=sys.stderr)
        return 2

    json_run = invoke(
        binary,
        "scan",
        str(FIXTURE),
        "--format",
        "json",
        "--exclude",
        "generated",
    )
    if json_run.returncode != 0:
        print(json_run.stderr, file=sys.stderr)
        return 1
    report = json.loads(json_run.stdout)
    assert report["schema"] == "apollyon.findings/v2"
    assert report["summary"]["complete"] is True
    assert report["summary"]["scanned_files"] == 4
    assert report["summary"]["excluded_files"] == 0
    assert report["summary"]["excluded_directories"] >= 2
    assert {finding["rule_id"] for finding in report["findings"]} == EXPECTED_RULES
    assert all(finding["snippet"] is None for finding in report["findings"])
    assert all(finding["engine"] in {"ast", "lexical"} for finding in report["findings"])
    assert all(finding["confidence"] in {"candidate", "tainted"} for finding in report["findings"])
    assert all(isinstance(finding["trace"], list) for finding in report["findings"])
    assert report["summary"]["ast_files"] + report["summary"]["lexical_files"] == report["summary"]["scanned_files"]
    assert all(not Path(finding["path"]).is_absolute() for finding in report["findings"])

    threshold_run = invoke(
        binary,
        "scan",
        str(FIXTURE),
        "--format",
        "json",
        "--exclude",
        "generated",
        "--fail-on",
        "high",
    )
    assert threshold_run.returncode == 1
    json.loads(threshold_run.stdout)

    with tempfile.TemporaryDirectory(prefix="apollyon-output-") as directory:
        output_path = Path(directory) / "results.sarif"
        sarif_run = invoke(
            binary,
            "scan",
            str(FIXTURE),
            "--format",
            "sarif",
            "--exclude",
            "generated",
            "--output",
            str(output_path),
        )
        assert sarif_run.returncode == 0
        assert sarif_run.stdout == ""
        sarif = json.loads(output_path.read_text(encoding="utf-8"))
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["invocations"][0]["executionSuccessful"] is True
        assert {result["ruleId"] for result in run["results"]} == EXPECTED_RULES

        output_path.write_text("preserve", encoding="utf-8")
        refusal = invoke(
            binary,
            "scan",
            str(FIXTURE),
            "--format",
            "sarif",
            "--exclude",
            "generated",
            "--output",
            str(output_path),
        )
        assert refusal.returncode == 2
        assert output_path.read_text(encoding="utf-8") == "preserve"

    with tempfile.TemporaryDirectory(prefix="apollyon-empty-") as directory:
        unsupported = Path(directory) / "notes.txt"
        unsupported.write_text("not supported source", encoding="utf-8")
        incomplete_run = invoke(binary, "scan", directory, "--format", "json")
        assert incomplete_run.returncode == 3
        incomplete = json.loads(incomplete_run.stdout)
        assert incomplete["summary"]["complete"] is False
        assert incomplete["errors"]

    rules_run = invoke(binary, "rules")
    assert rules_run.returncode == 0
    assert all(rule in rules_run.stdout for rule in EXPECTED_RULES)
    print("validated JSON, SARIF, exclusions, output files, and exit codes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
