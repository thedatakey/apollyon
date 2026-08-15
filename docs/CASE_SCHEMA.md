# Apollyon case schema

Every investigated root cause receives one case record. JSON producers should
use the same field names when practical.

```yaml
schema: apollyon.case/v1
case_id: APO-YYYY-NNNN
status: candidate # candidate | validated | remediated | verified | inconclusive
scope:
  repository: owner/name-or-local-id
  revision: commit-sha-or-working-tree
  authorized: true
claim:
  summary: bounded statement under investigation
  affected_locations: []
evidence:
  discovery: []
  reproducer: null
  assumptions: []
remediation:
  patch: null
  regression_tests: []
verification:
  method: null
  command: null
  bounds: []
  tool_versions: []
  result: not_run
limitations: []
```

A `verified` case means only that the documented reproducer/property was
blocked under the recorded assumptions and bounds. It does not certify the
entire program.
