#!/usr/bin/env python3
"""Generate honest, consistently formatted GitHub release notes."""

from pathlib import Path
import re
import sys


def extract_changes(version: str, changelog: str) -> str:
    """Return the Markdown inside the exact changelog version section."""
    lines = changelog.splitlines()
    prefix = f"## [{version}]"
    try:
        start = next(
            index for index, line in enumerate(lines) if line.startswith(prefix)
        )
    except StopIteration as error:
        raise ValueError(f"CHANGELOG.md has no release section for {version}") from error

    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if lines[index].startswith("## [")
        ),
        len(lines),
    )
    changes = "\n".join(lines[start + 1 : end]).strip()
    if not changes:
        raise ValueError(f"CHANGELOG.md release section for {version} is empty")
    return changes


def render_release_notes(version: str, changelog: str) -> str:
    """Render release Markdown without accidental code-block indentation."""
    if not re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", version):
        raise ValueError(f"invalid release version: {version}")

    changes = extract_changes(version, changelog)
    sections = (
        (
            f"Apollyon {version} is the first public pre-alpha release of the "
            "evidence-first source-security scanner."
        ),
        (
            "Findings are review candidates, not vulnerability verdicts. "
            "A complete scan is not proof that a project is secure."
        ),
        changes,
        "## Downloads",
        (
            "Choose the archive matching your platform. Each archive contains "
            "the executable, README, and MIT license."
        ),
        (
            "These binaries are currently unsigned. Verify the archive against "
            "`SHA256SUMS`. Build provenance is attached through GitHub artifact "
            "attestations and can be checked with `gh attestation verify`."
        ),
    )
    return "\n\n".join(sections) + "\n"


def main(arguments: list[str]) -> int:
    if len(arguments) != 4:
        print(
            "usage: generate_release_notes.py <vX.Y.Z> <changelog> <output>",
            file=sys.stderr,
        )
        return 2

    tag, changelog_path, output_path = arguments[1:]
    if not re.fullmatch(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", tag):
        print(f"error: invalid release tag: {tag}", file=sys.stderr)
        return 2

    try:
        notes = render_release_notes(
            tag[1:], Path(changelog_path).read_text(encoding="utf-8")
        )
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    try:
        Path(output_path).write_text(notes, encoding="utf-8")
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
