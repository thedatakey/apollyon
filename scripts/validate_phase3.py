#!/usr/bin/env python3
"""Exercise the Phase 3 candidate-to-verified fixture in Docker."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "phase3" / "python-eval"


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_phase3.py <trusted-apollyon-binary>")
    binary = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="apollyon-phase3-") as temporary:
        temporary = Path(temporary)
        source = temporary / "source"
        shutil.copytree(FIXTURE, source)
        original = (source / "app.py").read_bytes()
        cases = temporary / "cases"
        report = temporary / "findings.json"
        subprocess.run(
            [
                str(binary), "scan", str(source), "--format", "json", "--output", str(report),
                "--cases-dir", str(cases), "--authorized", "--repository", "fixture/phase3-python-eval",
                "--revision", "fixture-v1", "--no-gitignore",
            ],
            check=True,
        )
        findings = json.loads(report.read_text(encoding="utf-8"))
        tainted = [finding for finding in findings["findings"] if finding["confidence"] == "tainted"]
        if len(tainted) != 1 or len(tainted[0].get("case_refs", [])) != 1:
            raise SystemExit("fixture did not produce exactly one referenced tainted case")
        candidate = next(cases.glob("*.json"))
        verified_path = temporary / "verified.json"
        subprocess.run(
            [
                sys.executable, str(ROOT / "scripts" / "run_case_sandbox.py"),
                "--case", str(candidate), "--source-root", str(source), "--output", str(verified_path),
                "--adapter", "python-eval", "--propose-fix", "--formal-z3", "--fuzz-seconds", "1",
                "--timeout-seconds", "30",
            ],
            check=True,
        )
        verified = json.loads(verified_path.read_text(encoding="utf-8"))
        if verified.get("status") != "verified":
            raise SystemExit(f"unexpected final case status: {verified.get('status')}")
        if verified.get("transitions") != ["candidate", "validated", "remediated", "verified"]:
            raise SystemExit("case did not record the complete evidence transition")
        if verified["evidence"]["reproducer"].get("triggered") is not True:
            raise SystemExit("original reproducer did not trigger")
        if verified["verification"].get("original_trigger_blocked") is not True:
            raise SystemExit("patched reproducer was not blocked")
        if verified["verification"].get("result") != "passed":
            raise SystemExit("case verification did not pass")
        if verified["verification"].get("formal", {}).get("result") != "passed":
            raise SystemExit("bounded Z3 property did not pass")
        if verified["verification"].get("fuzzing", {}).get("result") != "passed":
            raise SystemExit("bounded Atheris comparison did not pass")
        if "ast.literal_eval" not in verified["remediation"].get("patch", ""):
            raise SystemExit("reviewable patch is missing the bounded replacement")
        if any(test.get("result") != "passed" for test in verified["remediation"]["regression_tests"]):
            raise SystemExit("a regression check did not pass")
        if (source / "app.py").read_bytes() != original:
            raise SystemExit("sandbox workflow modified the host target")
    print("validated Phase 3 candidate -> validated -> remediated -> verified workflow")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
