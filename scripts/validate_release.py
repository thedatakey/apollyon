#!/usr/bin/env python3
"""Validate Apollyon's public release metadata and distribution contract."""

import json
from pathlib import Path
import re
import struct
import sys
import tomllib

from generate_release_notes import render_release_notes


ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "x86_64-unknown-linux-musl",
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
}


def main() -> int:
    errors: list[str] = []
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    lockfile = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    version = cargo["package"]["version"]
    package = next(
        (
            item
            for item in lockfile["package"]
            if item["name"] == cargo["package"]["name"]
        ),
        None,
    )
    if package is None or package["version"] != version:
        errors.append("Cargo.lock package version differs from Cargo.toml")
    if cargo["package"].get("publish") is not False:
        errors.append("Cargo package must remain publish=false until crates.io is supported")

    plugin = json.loads(
        (ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    if plugin.get("version") != version:
        errors.append("Claude plugin version differs from Cargo.toml")

    citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
    if f"version: {version}" not in citation:
        errors.append("CITATION.cff version differs from Cargo.toml")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for required in (
        f"releases/tag/v{version}",
        "SHA256SUMS",
        "unsigned",
        "public pre-alpha",
    ):
        if required not in readme:
            errors.append(f"README.md is missing {required!r}")

    preview = ROOT / "docs" / "assets" / "apollyon-social-preview.png"
    contents = preview.read_bytes() if preview.is_file() else b""
    if len(contents) >= 24 and contents.startswith(b"\x89PNG\r\n\x1a\n"):
        width, height = struct.unpack(">II", contents[16:24])
        if (width, height) != (1280, 640):
            errors.append("social preview must be exactly 1280x640")
    else:
        errors.append("social preview is missing or is not a PNG")
    if len(contents) >= 1_000_000:
        errors.append("social preview must be smaller than 1 MB")

    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    for target in TARGETS:
        if target not in workflow:
            errors.append(f"release workflow is missing target {target}")
    if "pull_request:" in workflow:
        errors.append("release workflow must never run with write permissions from PRs")
    if (
        "contents: write" not in workflow
        or "attestations: write" not in workflow
        or "artifact-metadata: write" not in workflow
    ):
        errors.append("release job is missing narrowly scoped publication permissions")
    if "--verify-tag" not in workflow or "SHA256SUMS" not in workflow:
        errors.append("release workflow must verify its tag and publish checksums")
    if "merge-base --is-ancestor" not in workflow or "origin/main" not in workflow:
        errors.append("release workflow must require the tag commit to be on main")
    if "scripts/generate_release_notes.py" not in workflow:
        errors.append("release workflow must use the validated notes generator")

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    try:
        release_notes = render_release_notes(version, changelog)
    except ValueError as error:
        errors.append(str(error))
    else:
        expected_first_line = (
            f"Apollyon {version} is the first public pre-alpha release of the "
            "evidence-first source-security scanner."
        )
        if release_notes.splitlines()[0] != expected_first_line:
            errors.append("release notes have an unexpected or indented first line")
        if "\n## Downloads\n" not in release_notes:
            errors.append("release notes must contain an unindented Downloads heading")
        if not release_notes.endswith("\n"):
            errors.append("release notes must end with one newline")

    for line in workflow.splitlines():
        match = re.search(r"\buses:\s+([^\s]+)", line)
        if match and not re.fullmatch(r"[^@]+@[0-9a-f]{40}", match.group(1)):
            errors.append(f"release action is not pinned to a full commit: {match.group(1)}")

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"validated public release contract for Apollyon v{version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
