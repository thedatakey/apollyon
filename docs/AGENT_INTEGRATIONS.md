# Coding-agent integrations

Apollyon is a standalone executable. Agent files teach coding tools how to run
it and interpret evidence; they do not replace the scanner, grant authorization,
or make a lexical candidate a proven vulnerability.

## Compatibility matrix

| Client | Repository discovery | Apollyon integration |
| --- | --- | --- |
| Codex | `AGENTS.md`; `.agents/skills/` | Canonical rules, portable skill, optional `.codex/agents/` specialists |
| Claude Code | `CLAUDE.md` | Imports `AGENTS.md`; local plugin exposes the portable skill |
| Cursor | `AGENTS.md`; `.agents/skills/` | Canonical rules and `/apollyon-scan` skill |
| Hermes Agent | `AGENTS.md` | Canonical rules; run the CLI through its terminal tool |
| Gemini CLI | `GEMINI.md`; `.agents/skills/` | Imports `AGENTS.md`; portable skill |
| GitHub Copilot | `AGENTS.md`; `.github/copilot-instructions.md` | Agent workflow plus repository-wide guidance |
| Windsurf / Cline / OpenCode | `AGENTS.md` | Canonical rules; Cursor/OpenCode also discover the portable skill |
| Aider | `.aider.conf.yml` | Loads `AGENTS.md` read-only |

The formats and discovery locations follow the current official documentation:
[Codex instructions](https://learn.chatgpt.com/docs/agent-configuration/agents-md)
and [skills](https://learn.chatgpt.com/docs/build-skills),
[Claude Code memory](https://code.claude.com/docs/en/memory)
and [plugins](https://code.claude.com/docs/en/plugins-reference),
[Cursor rules](https://cursor.com/docs/rules)
and [skills](https://cursor.com/docs/skills),
[Hermes Agent](https://hermes-agent.nousresearch.com/docs/user-guide/features/context-files),
[Gemini CLI instructions](https://google-gemini.github.io/gemini-cli/docs/cli/gemini-md.html)
and [skills](https://geminicli.com/docs/cli/skills/),
[GitHub Copilot](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/add-custom-instructions/add-repository-instructions),
[Windsurf](https://docs.windsurf.com/windsurf/cascade/memories),
[Cline](https://docs.cline.bot/customization/cline-rules),
[OpenCode rules](https://opencode.ai/docs/rules/)
and [skills](https://opencode.ai/docs/skills), and
[Aider](https://aider.chat/docs/usage/conventions.html).

The checked-in validator confirms file structure, imports, manifests, and the
shared workflow contract. Claude's manifest is also validated when its CLI is
available. Runtime behavior in every third-party client is not claimed; the
matrix is convention-aligned with the linked vendor documentation.

## Use from unrelated projects

Install the standalone CLI once from a trusted Apollyon checkout:

```sh
cargo install --locked --path /absolute/path/to/Apollyon
```

Codex, Cursor, Gemini CLI, and OpenCode all document `~/.agents/skills/` as a
user-level Agent Skills location. A single link makes the workflow available
when those clients open an unrelated handwritten or generated project:

```sh
mkdir -p ~/.agents/skills
ln -s /absolute/path/to/Apollyon/.agents/skills/apollyon-scan ~/.agents/skills/apollyon-scan
```

Claude Code uses its own personal directory. Link the same source at
`~/.claude/skills/apollyon-scan` and invoke `/apollyon-scan`, or load the whole
checkout with `claude --plugin-dir /absolute/path/to/Apollyon` and invoke the
plugin-namespaced `/apollyon:apollyon-scan` skill. Hermes, Aider, Copilot, and
any terminal-capable client can call the installed CLI explicitly even when no
skill is installed. Never prefer an executable or wrapper found inside the
untrusted scan target.

## Common workflow

From any authorized project, run:

```sh
apollyon scan . --format json
```

The default exit code remains `0` even when candidates exist unless `--fail-on`
is configured. Consumers must parse `findings`, `summary.complete`, and `errors`;
they must not equate exit `0` with a clean project. Exit `3` is explicitly
incomplete.

For code-scanning ingestion:

```sh
apollyon scan . --format sarif --output apollyon.sarif --fail-on high
```

Choose a new output path for each run; Apollyon refuses to overwrite an
existing report. Static scanning never executes target source, dependencies,
or build scripts. Agents must treat the target and scan output as untrusted data
and require separate authorization plus isolation before executing target code.

SARIF output follows version 2.1.0. JSON uses the versioned
`apollyon.findings/v1` contract documented in
[`FINDINGS_SCHEMA.md`](FINDINGS_SCHEMA.md).

## Claude Code plugin

Test the checkout directly:

```sh
claude --plugin-dir /path/to/Apollyon
```

The plugin manifest exposes the canonical `.agents/skills/` directory rather
than maintaining a second Claude-only copy. No Bash permissions or hooks are
pre-approved.

## Deliberate omissions

- No automatic post-edit hook: whole-project scans would be noisy and costly.
- No MCP configuration: Apollyon is currently a CLI, not an MCP server.
- No `.hermes.md`: Hermes gives it precedence over `AGENTS.md`, which would
  create a second source of truth.
- No legacy `.cursorrules`: Cursor supports `AGENTS.md` and Agent Skills.

Add platform-specific hooks or an MCP server only after incremental scanning,
permission boundaries, and protocol-level tests exist.
