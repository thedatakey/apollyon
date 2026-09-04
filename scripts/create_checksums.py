#!/usr/bin/env python3
"""Create a deterministic checksum manifest for exactly four release archives."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: create_checksums.py <dist-directory>")
    directory = Path(sys.argv[1]).resolve(strict=True)
    archives = sorted([*directory.glob("apollyon-*.tar.gz"), *directory.glob("apollyon-*.zip")])
    if len(archives) != 4:
        raise SystemExit(f"expected exactly four archives, found {len(archives)}")
    output = directory / "SHA256SUMS"
    with output.open("x", encoding="ascii", newline="\n") as manifest:
        for archive in archives:
            manifest.write(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
