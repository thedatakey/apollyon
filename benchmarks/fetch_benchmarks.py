#!/usr/bin/env python3
"""Fetch pinned public benchmark source without executing target content."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import tempfile
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parent


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download(url: str, destination: Path, maximum_bytes: int) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Apollyon-Benchmark-Fetcher/0.3 (+https://github.com/thedatakey/apollyon)"},
    )
    with urllib.request.urlopen(request, timeout=60) as response, destination.open("xb") as output:
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > maximum_bytes:
                raise ValueError(f"download exceeded {maximum_bytes} bytes: {url}")
            output.write(chunk)


def write_file(root: Path, relative: str, data: bytes) -> None:
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe archive path: {relative}")
    target = root.joinpath(*path.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: fetch_benchmarks.py <new-output-directory>")
    output = Path(sys.argv[1])
    output.mkdir(mode=0o700)
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))

    with tempfile.TemporaryDirectory(prefix="apollyon-benchmarks-") as temporary:
        temporary = Path(temporary)
        owasp = manifest["owasp"]
        archive = temporary / "owasp.zip"
        download(
            f"https://github.com/OWASP-Benchmark/BenchmarkJava/archive/{owasp['revision']}.zip",
            archive,
            300 * 1024 * 1024,
        )
        root_name = f"BenchmarkJava-{owasp['revision']}"
        wanted_prefix = f"{root_name}/{owasp['source']}/"
        labels_name = f"{root_name}/{owasp['labels']}"
        with zipfile.ZipFile(archive) as bundle:
            labels = bundle.read(labels_name)
            if digest(labels) != owasp["labels_sha256"]:
                raise ValueError("OWASP labels hash mismatch")
            write_file(output / "owasp", owasp["labels"], labels)
            for info in bundle.infolist():
                if info.filename.startswith(wanted_prefix) and info.filename.endswith(".java"):
                    relative = info.filename.removeprefix(wanted_prefix)
                    write_file(output / "owasp" / "source", relative, bundle.read(info))

        juliet = manifest["juliet"]
        archive = temporary / "juliet.zip"
        download(juliet["url"], archive, 200 * 1024 * 1024)
        if digest(archive.read_bytes()) != juliet["archive_sha256"]:
            raise ValueError("NIST Juliet archive hash mismatch")
        with zipfile.ZipFile(archive) as bundle:
            for relative in juliet["selected_files"]:
                data = bundle.read(juliet["source_prefix"] + relative)
                if digest(data) != juliet["selected_sha256"][relative]:
                    raise ValueError(f"NIST Juliet selected-file hash mismatch: {relative}")
                write_file(output / "juliet", relative, data)

        cve = manifest["cve"]
        for label, revision, expected in [
            ("vulnerable", cve["vulnerable_revision"], cve["vulnerable_sha256"]),
            ("fixed", cve["fixed_revision"], cve["fixed_sha256"]),
        ]:
            url = f"https://raw.githubusercontent.com/icip-cas/PPTAgent/{revision}/{cve['path']}"
            path = temporary / f"cve-{label}.py"
            download(url, path, 2 * 1024 * 1024)
            data = path.read_bytes()
            if digest(data) != expected:
                raise ValueError(f"{cve['cve']} {label} source hash mismatch")
            write_file(output / "cve", f"{cve['cve']}-{label}.py", data)

    print(f"fetched and verified public benchmark source in {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
