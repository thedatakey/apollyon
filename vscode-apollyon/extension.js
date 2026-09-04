"use strict";

const vscode = require("vscode");
const { parseSarif, safeParts } = require("./sarif");

function severity(level) {
  return level === "error"
    ? vscode.DiagnosticSeverity.Error
    : level === "note"
      ? vscode.DiagnosticSeverity.Information
      : vscode.DiagnosticSeverity.Warning;
}

async function refresh(collection) {
  collection.clear();
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) return;
  const configured = vscode.workspace.getConfiguration("apollyon").get("sarifPath", "apollyon.sarif");
  const report = vscode.Uri.joinPath(folder.uri, ...safeParts(configured));
  let bytes;
  try {
    bytes = await vscode.workspace.fs.readFile(report);
  } catch (error) {
    if (error instanceof vscode.FileSystemError && error.code === "FileNotFound") return;
    throw error;
  }
  const findings = parseSarif(JSON.parse(Buffer.from(bytes).toString("utf8")));
  const grouped = new Map();
  for (const finding of findings) {
    const target = vscode.Uri.joinPath(folder.uri, ...safeParts(finding.uri));
    const line = finding.line - 1;
    const diagnostic = new vscode.Diagnostic(
      new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER),
      `${finding.ruleId}: ${finding.message}`,
      severity(finding.level),
    );
    diagnostic.source = "Apollyon";
    diagnostic.code = finding.ruleId;
    const key = target.toString();
    if (!grouped.has(key)) grouped.set(key, { target, diagnostics: [] });
    grouped.get(key).diagnostics.push(diagnostic);
  }
  for (const { target, diagnostics } of grouped.values()) collection.set(target, diagnostics);
}

function activate(context) {
  const diagnostics = vscode.languages.createDiagnosticCollection("apollyon");
  context.subscriptions.push(diagnostics);
  context.subscriptions.push(vscode.commands.registerCommand("apollyon.refreshSarif", () => refresh(diagnostics)));
  context.subscriptions.push(vscode.workspace.onDidChangeConfiguration((event) => {
    if (event.affectsConfiguration("apollyon.sarifPath")) refresh(diagnostics);
  }));
  refresh(diagnostics);
}

function deactivate() {}

module.exports = { activate, deactivate };
