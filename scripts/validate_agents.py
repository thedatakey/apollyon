#!/usr/bin/env python3
"""Validate Apollyon's project-scoped Codex agent definitions."""

from pathlib import Path
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
AGENT_DIR = ROOT / ".codex" / "agents"
PROFILE_DIR = ROOT / "agents"
REQUIRED = {"name", "description", "developer_instructions"}
ALLOWED_SANDBOXES = {"read-only", "workspace-write"}
ALLOWED_EFFORTS = {"low", "medium", "high", "xhigh", "max", "ultra"}
PROFILE_SECTIONS = {
    "# Identity & Memory",
    "## Core Mission",
    "## Critical Rules",
    "## Technical Deliverables",
    "## Workflow Process",
    "## Success Metrics",
}


def profile_frontmatter(path: Path) -> tuple[dict[str, str], str]:
    text = path.read_text(encoding="utf-8")
    parts = text.split("---", 2)
    if len(parts) != 3 or parts[0].strip():
        raise ValueError("missing YAML frontmatter")
    metadata: dict[str, str] = {}
    for line in parts[1].splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            metadata[key.strip()] = value.strip().strip('"')
    return metadata, parts[2]


def main() -> int:
    errors: list[str] = []
    paths = sorted(AGENT_DIR.glob("*.toml"))
    if not paths:
        errors.append("no custom agents found")
    names: set[str] = set()
    for path in paths:
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            errors.append(f"{path.relative_to(ROOT)}: {error}")
            continue
        missing = REQUIRED - data.keys()
        if missing:
            errors.append(f"{path.name}: missing {', '.join(sorted(missing))}")
        for key in REQUIRED:
            if key in data and (not isinstance(data[key], str) or not data[key].strip()):
                errors.append(f"{path.name}: {key} must be a non-empty string")
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{path.name}: name must be a non-empty string")
        elif name in names:
            errors.append(f"{path.name}: duplicate agent name {name!r}")
        else:
            names.add(name)
        profile_path = PROFILE_DIR / f"{path.stem}.md"
        try:
            profile, body = profile_frontmatter(profile_path)
        except (OSError, ValueError) as error:
            errors.append(f"{profile_path.relative_to(ROOT)}: {error}")
        else:
            for key in ("name", "description", "color", "emoji", "vibe"):
                if not profile.get(key):
                    errors.append(f"{profile_path.name}: missing {key} frontmatter")
            if profile.get("name") != name:
                errors.append(f"{profile_path.name}: name differs from runtime TOML")
            if profile.get("description") != data.get("description"):
                errors.append(f"{profile_path.name}: description differs from runtime TOML")
            for section in PROFILE_SECTIONS:
                if section not in body:
                    errors.append(f"{profile_path.name}: missing section {section!r}")
        sandbox = data.get("sandbox_mode")
        if sandbox is not None and sandbox not in ALLOWED_SANDBOXES:
            errors.append(f"{path.name}: unsupported sandbox_mode {sandbox!r}")
        model = data.get("model")
        if model is not None and (not isinstance(model, str) or not model.strip()):
            errors.append(f"{path.name}: model must be a non-empty string")
        effort = data.get("model_reasoning_effort")
        if effort is not None and effort not in ALLOWED_EFFORTS:
            errors.append(f"{path.name}: unsupported model_reasoning_effort {effort!r}")
    runtime_stems = {path.stem for path in paths}
    profile_stems = {path.stem for path in PROFILE_DIR.glob("*.md")}
    for stem in sorted(runtime_stems - profile_stems):
        errors.append(f"{stem}.toml: missing matching profile")
    for stem in sorted(profile_stems - runtime_stems):
        errors.append(f"{stem}.md: missing matching runtime agent")
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"validated {len(paths)} Codex agent definitions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
