#!/usr/bin/env python3
"""Validate Phase 4 benchmark and distribution contracts."""

from __future__ import annotations

import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    errors = []
    manifest = json.loads((ROOT / "benchmarks" / "manifest.json").read_text(encoding="utf-8"))
    truth = json.loads((ROOT / "benchmarks" / "ground-truth.json").read_text(encoding="utf-8"))
    result = json.loads((ROOT / "benchmarks" / "results" / "v0.2.0-phase4.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != "apollyon.benchmarks/manifest/v1":
        errors.append("unexpected benchmark manifest schema")
    if truth.get("schema") != "apollyon.benchmarks/ground-truth/v1":
        errors.append("unexpected ground-truth schema")
    if result.get("schema") != "apollyon.benchmarks/results/v1":
        errors.append("unexpected benchmark result schema")
    for corpus in ("owasp", "juliet", "cve"):
        if result.get("corpora", {}).get(corpus, {}).get("coverage", {}).get("complete") is not True:
            errors.append(f"published {corpus} scan is not complete")
        for metric in result.get("corpora", {}).get(corpus, {}).get("metrics", []):
            if any(metric.get(name, -1) < 0 for name in ("tp", "fp", "tn", "fn")):
                errors.append(f"negative metric count in {corpus}")
    if len(manifest.get("juliet", {}).get("selected_files", [])) != 9 or len(truth.get("juliet", [])) != 18:
        errors.append("Juliet selection/labels changed without a benchmark update")

    action = (ROOT / ".github" / "actions" / "apollyon" / "action.yml").read_text(encoding="utf-8")
    for required in ("fail-on:", "baseline:", "upload-sarif:", "github/codeql-action/upload-sarif@"):
        if required not in action:
            errors.append(f"composite Action missing {required}")
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    for required in (
        "cosign sign-blob",
        "SHA256SUMS.sigstore.json",
        "subject-checksums:",
        "Verify reproducible",
        "scripts/validate_phase4.py",
        "node --test vscode-apollyon/test/*.test.js",
    ):
        if required not in release:
            errors.append(f"release workflow missing {required}")
    for line in [*action.splitlines(), *release.splitlines()]:
        match = re.search(r"uses:\s+([^\s]+)@([^\s#]+)", line)
        if match and not re.fullmatch(r"[0-9a-f]{40}", match.group(2)):
            errors.append(f"external action is not pinned to a commit: {match.group(0)}")

    hooks = (ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
    if "language: rust" not in hooks or "pass_filenames: false" not in hooks:
        errors.append("pre-commit hook contract is incomplete")
    extension = json.loads((ROOT / "vscode-apollyon" / "package.json").read_text(encoding="utf-8"))
    if extension.get("main") != "./extension.js" or "apollyon.refreshSarif" not in json.dumps(extension):
        errors.append("VS Code extension manifest is incomplete")

    if errors:
        for error in errors:
            print(f"error: {error}")
        return 1
    print("validated Phase 4 benchmark and distribution contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
