#!/usr/bin/env python3
"""Validate Apollyon's portable coding-agent integration surfaces."""

import json
from pathlib import Path
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / ".agents" / "skills" / "apollyon-scan" / "SKILL.md"


def frontmatter(path: Path) -> tuple[dict[str, str], str]:
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


def first_content_line(path: Path) -> str:
    return next(
        (line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()),
        "",
    )


def main() -> int:
    errors: list[str] = []
    required = [
        ROOT / "AGENTS.md",
        ROOT / "CLAUDE.md",
        ROOT / "GEMINI.md",
        ROOT / ".aider.conf.yml",
        ROOT / ".github" / "copilot-instructions.md",
        ROOT / ".claude-plugin" / "plugin.json",
        SKILL,
        SKILL.parent / "agents" / "openai.yaml",
        ROOT / "docs" / "AGENT_INTEGRATIONS.md",
        ROOT / "docs" / "FINDINGS_SCHEMA.md",
    ]
    for path in required:
        if not path.is_file():
            errors.append(f"missing {path.relative_to(ROOT)}")

    if first_content_line(ROOT / "CLAUDE.md") != "@AGENTS.md":
        errors.append("CLAUDE.md must import @AGENTS.md first")
    if first_content_line(ROOT / "GEMINI.md") != "@./AGENTS.md":
        errors.append("GEMINI.md must import @./AGENTS.md first")

    agents_text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    if "primary Codex task" in agents_text:
        errors.append("AGENTS.md still contains Codex-only orchestration wording")
    if "apollyon scan <path> --format json" not in agents_text:
        errors.append("AGENTS.md is missing the portable scan command")

    try:
        metadata, body = frontmatter(SKILL)
    except (OSError, ValueError) as error:
        errors.append(f"{SKILL.relative_to(ROOT)}: {error}")
    else:
        if set(metadata) != {"name", "description"}:
            errors.append("SKILL.md frontmatter must contain only name and description")
        if metadata.get("name") != "apollyon-scan":
            errors.append("SKILL.md name must match its directory")
        description = metadata.get("description", "")
        if not description or "authorized" not in description.lower():
            errors.append("SKILL.md description must require an authorized target")
        for phrase in ("Exit `3`", "--format json", "--include-snippets"):
            if phrase not in body:
                errors.append(f"SKILL.md is missing {phrase!r}")

    try:
        manifest = json.loads(
            (ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
        )
        cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        errors.append(f"manifest parse error: {error}")
    else:
        if manifest.get("name") != "apollyon":
            errors.append("Claude plugin name must be apollyon")
        if manifest.get("skills") != "./.agents/skills/":
            errors.append("Claude plugin must reuse the canonical Agent Skills directory")
        if manifest.get("version") != cargo["package"]["version"]:
            errors.append("Claude plugin and Cargo package versions differ")

    if (ROOT / ".hermes.md").exists():
        errors.append(".hermes.md would override the canonical AGENTS.md workflow")

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("validated portable integration file structure and manifests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
