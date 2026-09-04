#!/usr/bin/env python3
"""Create normalized release archives for a built Apollyon binary."""

from __future__ import annotations

import argparse
import gzip
import io
from pathlib import Path
import tarfile
import time
import zipfile


ROOT = Path(__file__).resolve().parents[1]


def entries(binary: Path, package: str, windows: bool) -> list[tuple[str, bytes, int]]:
    name = "apollyon.exe" if windows else "apollyon"
    return [
        (f"{package}/{name}", binary.read_bytes(), 0o755),
        (f"{package}/LICENSE", (ROOT / "LICENSE").read_bytes(), 0o644),
        (f"{package}/README.md", (ROOT / "README.md").read_bytes(), 0o644),
    ]


def write_tar(path: Path, package: str, files: list[tuple[str, bytes, int]], epoch: int) -> None:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
        directory = tarfile.TarInfo(package)
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        directory.uid = directory.gid = 0
        directory.uname = directory.gname = "root"
        directory.mtime = epoch
        archive.addfile(directory)
        for name, data, mode in sorted(files):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = epoch
            archive.addfile(info, io.BytesIO(data))
    with path.open("xb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=epoch, compresslevel=9) as compressed:
            compressed.write(raw.getvalue())


def write_zip(path: Path, package: str, files: list[tuple[str, bytes, int]], epoch: int) -> None:
    timestamp = time.gmtime(max(epoch, 315532800))[:6]
    with zipfile.ZipFile(path, mode="x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data, mode in sorted(files):
            info = zipfile.ZipInfo(name, timestamp)
            info.create_system = 3
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--format", required=True, choices=["tar.gz", "zip"])
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--output-directory", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    args.output_directory.mkdir(parents=True, exist_ok=True)
    package = f"apollyon-v{args.version}-{args.target}"
    output = args.output_directory / f"{package}.{args.format}"
    files = entries(binary, package, args.format == "zip")
    if args.format == "zip":
        write_zip(output, package, files, args.source_date_epoch)
    else:
        write_tar(output, package, files, args.source_date_epoch)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
