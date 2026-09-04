"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { parseSarif, safeParts } = require("../sarif");

test("parses valid findings and skips incomplete locations", () => {
  const findings = parseSarif({
    version: "2.1.0",
    runs: [{ results: [
      { ruleId: "APO004", level: "error", message: { text: "review eval" }, locations: [{ physicalLocation: { artifactLocation: { uri: "src/app.py" }, region: { startLine: 7 } } }] },
      { ruleId: "APO005", message: { text: "missing location" } },
    ] }],
  });
  assert.deepEqual(findings, [{ ruleId: "APO004", level: "error", message: "review eval", uri: "src/app.py", line: 7 }]);
});

test("rejects non-SARIF input", () => {
  assert.throws(() => parseSarif({ version: "1.0" }), /SARIF 2.1.0/);
});

test("accepts workspace-relative SARIF paths", () => {
  assert.deepEqual(safeParts("src/lib.rs"), ["src", "lib.rs"]);
  assert.deepEqual(safeParts("src%2Fmain.rs"), ["src", "main.rs"]);
});

test("rejects absolute and parent-traversing SARIF paths", () => {
  for (const path of ["/etc/passwd", "../secret", "src/../../secret", "C:\\secret"])
    assert.throws(() => safeParts(path), /not workspace-relative/);
});
