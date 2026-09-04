#!/usr/bin/env python3
"""Run an Apollyon case adapter in an enforced disposable Docker sandbox."""

from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import uuid


IMAGE = "apollyon-phase3-tools:1"
BASE_IMAGE = "python@sha256:5f55cdf0c5d9dc1a415637a5ccc4a9e18663ad203673173b8cda8f8dcacef689"
EXPECTED_LABELS = {
    "org.opencontainers.image.version": "1",
    "io.apollyon.atheris": "3.0.0",
    "io.apollyon.z3-solver": "4.15.3.0",
}
MAX_CASE_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_SOURCE_FILES = 128


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, **kwargs)


def safe_location(case: dict, source_root: Path) -> tuple[PurePosixPath, Path]:
    if case.get("schema") != "apollyon.case/v1" or case.get("status") != "candidate":
        raise ValueError("input must be an apollyon.case/v1 candidate")
    if case.get("scope", {}).get("authorized") is not True:
        raise ValueError("case scope must record explicit authorization")
    discovery = case.get("evidence", {}).get("discovery", [])
    if len(discovery) != 1 or discovery[0].get("rule_id") != "APO004" or discovery[0].get("confidence") != "tainted":
        raise ValueError("python-eval/v1 requires one tainted APO004 discovery record")
    locations = case.get("claim", {}).get("affected_locations", [])
    if len(locations) != 1:
        raise ValueError("python-eval/v1 requires exactly one affected location")
    relative = PurePosixPath(locations[0].get("path", ""))
    if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("affected path must be a normalized relative path")
    target = source_root.joinpath(*relative.parts)
    root = source_root.resolve(strict=True)
    resolved = target.resolve(strict=True)
    if resolved.parent != root and root not in resolved.parents:
        raise ValueError("affected path escapes the authorized source root")
    if target.is_symlink() or not target.is_file() or target.suffix != ".py":
        raise ValueError("python-eval/v1 requires a regular non-symlink Python file")
    return relative, target


def archive_inputs(worker: Path, fuzzer: Path, case_path: Path, source_root: Path) -> bytes:
    buffer = io.BytesIO()
    total = 0
    count = 0
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for source, arcname in [(worker, "worker.py"), (fuzzer, "atheris_worker.py"), (case_path, "case.json")]:
            archive.add(source, arcname=arcname, recursive=False)
        for path in sorted(source_root.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"source tree contains a symbolic link: {path.relative_to(source_root)}")
            if path.is_dir():
                relative = path.relative_to(source_root)
                archive.add(path, arcname=str(PurePosixPath("source", *relative.parts)), recursive=False)
                continue
            if not path.is_file():
                continue
            count += 1
            total += path.stat().st_size
            if count > MAX_SOURCE_FILES or total > MAX_SOURCE_BYTES:
                raise ValueError("source tree exceeds the python-eval/v1 sandbox copy bound")
            relative = path.relative_to(source_root)
            archive.add(path, arcname=str(PurePosixPath("source", *relative.parts)), recursive=False)
    return buffer.getvalue()


def verify_container(docker: str, name: str) -> None:
    inspected = json.loads(run([docker, "inspect", name], capture_output=True, text=True).stdout)[0]
    host = inspected["HostConfig"]
    if host.get("NetworkMode") != "none" or host.get("ReadonlyRootfs") is not True:
        raise RuntimeError("sandbox inspection rejected network or root-filesystem settings")
    if "ALL" not in (host.get("CapDrop") or []) or "no-new-privileges" not in (host.get("SecurityOpt") or []):
        raise RuntimeError("sandbox inspection rejected privilege settings")
    if host.get("Memory") != 256 * 1024 * 1024 or host.get("MemorySwap") != 256 * 1024 * 1024:
        raise RuntimeError("sandbox inspection rejected memory bounds")
    if host.get("NanoCpus") != 1_000_000_000 or host.get("PidsLimit") != 64:
        raise RuntimeError("sandbox inspection rejected CPU or process bounds")
    if inspected.get("Mounts"):
        raise RuntimeError("sandbox inspection found a host mount or volume")
    if "/case" not in (host.get("Tmpfs") or {}):
        raise RuntimeError("sandbox inspection found no disposable /case storage")


def inspect_tools_image(docker: str) -> str:
    inspected = json.loads(run([docker, "image", "inspect", IMAGE], capture_output=True, text=True).stdout)[0]
    labels = inspected.get("Config", {}).get("Labels") or {}
    for key, expected in EXPECTED_LABELS.items():
        if labels.get(key) != expected:
            raise RuntimeError(f"tools image label {key} did not equal {expected}")
    image_id = inspected.get("Id", "")
    if not image_id.startswith("sha256:"):
        raise RuntimeError("tools image did not expose a content-addressed image ID")
    return image_id


def write_new(path: Path, contents: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(contents)
        output.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--adapter", choices=["python-eval"], required=True)
    parser.add_argument("--propose-fix", action="store_true")
    parser.add_argument("--formal-z3", action="store_true")
    parser.add_argument("--fuzz-seconds", type=int, default=0)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 60:
        raise SystemExit("--timeout-seconds must be between 1 and 60")
    if not 0 <= args.fuzz_seconds <= 5:
        raise SystemExit("--fuzz-seconds must be between 0 and 5")
    if (args.formal_z3 or args.fuzz_seconds) and not args.propose_fix:
        raise SystemExit("formal and fuzz verification require --propose-fix")
    if args.output.exists() or not args.output.parent.is_dir():
        raise SystemExit("--output must be a new file in an existing directory")
    if args.case.stat().st_size > MAX_CASE_BYTES:
        raise SystemExit("case record exceeds 1 MiB")
    case = json.loads(args.case.read_text(encoding="utf-8"))
    relative, _target = safe_location(case, args.source_root)
    worker = Path(__file__).with_name("case_worker.py").resolve(strict=True)
    fuzzer = Path(__file__).with_name("atheris_worker.py").resolve(strict=True)
    archive = archive_inputs(worker, fuzzer, args.case.resolve(strict=True), args.source_root.resolve(strict=True))
    docker = shutil.which("docker")
    if docker is None:
        raise SystemExit("trusted Docker CLI was not found on PATH")
    image_id = inspect_tools_image(docker)
    name = f"apollyon-case-{os.getpid()}-{uuid.uuid4().hex[:10]}"
    create = [
        docker, "run", "--detach", "--name", name,
        "--network", "none", "--read-only", "--user", "65534:65534",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--cpus", "1", "--memory", "256m", "--memory-swap", "256m",
        "--pids-limit", "64", "--tmpfs", "/case:rw,noexec,nosuid,nodev,size=16m",
        "--env", "APOLLYON_SANDBOX=1", image_id, "sleep", "120",
    ]
    try:
        run(create, stdout=subprocess.DEVNULL)
        verify_container(docker, name)
        run(
            [docker, "exec", "--interactive", name, "tar", "--no-same-owner", "-C", "/case", "-xf", "-"],
            input=archive,
            stdout=subprocess.DEVNULL,
        )
        command = [docker, "exec", name, "python", "/case/worker.py", "/case/case.json", f"/case/source/{relative}"]
        if args.propose_fix:
            command.append("--propose-fix")
        if args.formal_z3:
            command.append("--formal-z3")
        if args.fuzz_seconds:
            command.extend(["--fuzz-seconds", str(args.fuzz_seconds)])
        completed = run(command, capture_output=True, text=True, timeout=args.timeout_seconds)
        result = json.loads(completed.stdout)
        if result.get("schema") != "apollyon.case/v1" or result.get("case_id") != case.get("case_id"):
            raise RuntimeError("sandbox returned a mismatched case record")
        result.setdefault("evidence", {})["sandbox"] = {
            "image": IMAGE,
            "image_id": image_id,
            "base_image": BASE_IMAGE,
            "network": "none",
            "host_mounts": 0,
            "read_only_root": True,
            "user": "65534:65534",
            "capabilities_dropped": ["ALL"],
            "no_new_privileges": True,
            "cpus": 1,
            "memory_bytes": 256 * 1024 * 1024,
            "pids": 64,
            "wall_time_seconds": args.timeout_seconds,
            "writable_storage": "16 MiB disposable tmpfs",
        }
        if result.get("verification", {}).get("tool_versions") is not None:
            result["verification"]["tool_versions"].append(f"tools image {image_id}")
        write_new(args.output, json.dumps(result, indent=2, sort_keys=True))
    finally:
        subprocess.run([docker, "rm", "--force", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
