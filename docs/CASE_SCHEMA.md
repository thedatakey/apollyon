# Apollyon case schema

Every investigated root cause receives one case record. JSON producers should
use the same field names when practical.

```yaml
schema: apollyon.case/v1
case_id: APO-YYYY-NNNN
status: candidate # candidate | validated | remediated | verified | inconclusive
transitions: [candidate]
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
  sandbox: null
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

## State transitions

The valid forward sequence is `candidate → validated → remediated → verified`.
`inconclusive` is terminal for the recorded attempt. `transitions` retains the
states actually reached. A generated Phase 3 case starts at `candidate`; its
`reproducer` is `null`, and its assumptions explicitly state that target code
has not run. A reproducer that does not trigger preserves `candidate` and adds
the reason to `limitations`.

`validated` means only that the recorded reproducer fired in the recorded
sandbox. `remediated` means a patch was applied to a disposable copy for the
case workflow; the original target remains unchanged. `verified` means only
that the original recorded trigger was blocked and the recorded regression
checks passed on that disposable copy under the listed bounds.

## Phase 3 Python-eval adapter

The first adapter is deliberately narrow. It accepts one authorized, tainted
APO004 case mapped to a function-local Python `eval` call. It supports a
zero-argument function reading `input()` or a function with one positional
argument. The reproducer uses a fixed payload whose success is a marker in the
container's disposable filesystem. The remediation replaces only that call
with `ast.literal_eval`, emits a unified diff, reruns the original reproducer,
checks a literal-input regression, and runs checked-in `unittest` tests.

Optional `--formal-z3` records a bounded syntax-identity property, its explicit
encoding assumptions, solver result, and Z3 version. Optional
`--fuzz-seconds 1..5` records an Atheris comparison of the original and patched
copies, including the controlled triggering input, input hash, crash-artifact
count, process result, engine version, and time budget. These fields live under
`verification.formal` and `verification.fuzzing`; absence means the optional
adapter was not requested.

The output's `evidence.sandbox` records the immutable image digest and enforced
network, mount, privilege, CPU, memory, process, wall-time, and storage bounds.
See [SANDBOX.md](SANDBOX.md) for the controller threat model and command.
