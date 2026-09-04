#!/usr/bin/env python3
"""Run static benchmark scans and produce deterministic measurements."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--corpora", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--scanner-revision", required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    corpora = args.corpora.resolve(strict=True)
    args.output_directory.mkdir(mode=0o700)
    reports = {}
    for name in ("owasp", "juliet", "cve"):
        report = args.output_directory / f"{name}.json"
        subprocess.run(
            [str(binary), "scan", str(corpora / name / ("source" if name == "owasp" else "")),
             "--format", "json", "--output", str(report), "--no-gitignore"],
            check=True,
            stdin=subprocess.DEVNULL,
        )
        reports[name] = report
    subprocess.run(
        [sys.executable, str(ROOT / "score.py"),
         "--owasp-report", str(reports["owasp"]),
         "--owasp-labels", str(corpora / "owasp" / "expectedresults-1.2.csv"),
         "--juliet-report", str(reports["juliet"]),
         "--cve-report", str(reports["cve"]),
         "--scanner-revision", args.scanner_revision,
         "--output", str(args.output_directory / "results.json")],
        check=True,
    )
    print(args.output_directory / "results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
