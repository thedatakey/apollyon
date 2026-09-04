"use strict";

function safeParts(uri) {
  const decoded = decodeURIComponent(uri.replaceAll("\\", "/"));
  const parts = decoded.split("/");
  if (
    decoded.startsWith("/") ||
    /^[A-Za-z][A-Za-z0-9+.-]*:/.test(decoded) ||
    parts.some((part) => part === "" || part === "." || part === "..")
  ) {
    throw new Error(`SARIF location is not workspace-relative: ${uri}`);
  }
  return parts;
}

function parseSarif(document) {
  if (!document || document.version !== "2.1.0" || !Array.isArray(document.runs)) {
    throw new Error("Expected a SARIF 2.1.0 document");
  }
  const findings = [];
  for (const run of document.runs) {
    for (const result of run.results || []) {
      const location = result.locations?.[0]?.physicalLocation;
      const uri = location?.artifactLocation?.uri;
      const line = location?.region?.startLine;
      if (typeof uri !== "string" || !Number.isInteger(line) || line < 1) continue;
      findings.push({
        ruleId: typeof result.ruleId === "string" ? result.ruleId : "Apollyon",
        level: ["error", "warning", "note"].includes(result.level) ? result.level : "warning",
        message: result.message?.text || "Apollyon review candidate",
        uri,
        line,
      });
    }
  }
  return findings;
}

module.exports = { parseSarif, safeParts };
