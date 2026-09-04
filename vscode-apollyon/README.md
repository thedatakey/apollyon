# Apollyon SARIF for VS Code

This source extension reads an `apollyon.sarif` file from the first workspace
folder and renders its results as diagnostics on the recorded source lines.
Change `apollyon.sarifPath` for a different workspace-relative report, or run
**Apollyon: Refresh SARIF Diagnostics** after generating a new report.

Generate the input without source snippets:

```sh
apollyon scan . --format sarif --output apollyon.sarif
```

For local development, open this folder in VS Code and press F5 to launch an
Extension Development Host. The parser tests use only Node's built-in test
runner:

```sh
npm test
```

The viewer does not execute Apollyon or target code. It rejects absolute and
parent-traversing SARIF paths before mapping diagnostics into the workspace.
