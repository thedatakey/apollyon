# Rule boundaries

All 22 rules produce review candidates. A successful tree-sitter parse
filters candidates to relevant syntax nodes. Recovered trees retain valid
expressions; damaged expressions and parser failures use lexical analysis. Bounded taint analysis can raise confidence to
`tainted` (modeled remote source) or `reachable` (modeled local source) for supported flow rules. Neither status proves
exploitability or framework behavior. Comments and ordinary strings are removed
from the code view; rules APO007–APO012 also consume lexer-classified literal
metadata. Complex interpolation and full program semantics remain outside the
guarantees.

| Rule | Severity | Implemented Phase 1 boundary |
| --- | --- | --- |
| APO007 | high | Literal private-key header, bounded known credential prefixes, immediate literal assignment of at least 8 characters to a credential name, including underscore/camelCase segments. Common placeholders are excluded. Standalone entropy is not a credential signal. |
| APO008 | medium | MD5, SHA1/SHA-1, DES/TripleDES/3DES, RC4, ECB identifiers, or matching algorithm literals on a line with a recognized crypto factory call. Explicit Python `usedforsecurity=False` excludes the match. |
| APO009 | info | Non-cryptographic random calls in C/C++, JS/TS, Python, JVM, and PHP. Their use may be harmless. |
| APO010 | high | Literal TLS-disable flags, SSL_VERIFY_NONE, Node TLS environment disabling, same-line accepting HostnameVerifier, or empty same-line checkServerTrusted body. |
| APO011 | medium | Same-line SQL construction, or a tracked input-derived first argument passed to execute/executemany/query/rawQuery across lines. Bound parameter arguments do not themselves qualify. |
| APO012 | medium | A modeled input flow into the first filesystem-call argument. Ordinary variable paths and unrelated `.open` receivers are excluded. This is bounded evidence, not a traversal verdict. |

The full Phase 1 token lists live in `src/rules/patterns.rs`. Existing APO001–006
retain their lexical matcher behavior before AST validation, including
the C# 20-line formatter window. Run `apollyon rules` for descriptions and
language scope. See [the findings schema](FINDINGS_SCHEMA.md) for engine,
confidence, trace, fallback, and analysis-bound contracts.

Secret evidence is never included for a line matched by APO007, even with
`--include-snippets`, and even if that rule is disabled or suppressed. Other
findings on that line are also redacted. This is conservative redaction of
recognized candidates, not a guarantee of detecting every possible secret.

APO005 additionally recognizes direct `require('child_process')` calls, namespace
requires/imports, and destructured/named imports with aliases. Imported `exec`
and `execSync` are high severity; argv-oriented APIs are info. Explicit Python
`shell=True`, `os.system`, and `os.popen` are high; Python list arguments are
info. Explicit severity overrides still win. Import shadowing, reassignment,
and general module resolution remain outside this bounded model.

File/deserialization reads are no longer implicit taint sources. Local input
such as argv, environment, and stdin is still modeled; `tainted` must not be
interpreted as proof of remote attacker control. Direct source and sink can
legitimately occur on the same line, for example `open(request.args['path'])`.

Limits: named assignments and crypto factories are same-line associations;
provider prefixes use minimum length and character checks, not issuer validation
or checksums. General custom trust-manager bodies, path aliases/overloads,
branch-sensitive flow, and full SQL expression semantics are not resolved. Use suppression/config controls with explicit accounting,
then independently review candidates. No measured accuracy claim is made.

## Audit upgrade families

| Rule | Default severity | Bounded candidate |
| --- | --- | --- |
| APO013 | high | Literal credential under a browser-public variable prefix |
| APO014 | high | Explicit enabled debug configuration |
| APO015 | high | Modeled input reaching selected HTML/template sinks |
| APO016 | high | Modeled input reaching selected HTTP request APIs |
| APO017 | high | Explicit disabled JWT verification or none algorithm |
| APO018 | high | Explicit wildcard origin and credentials on one line |
| APO019 | high | Explicit disabled cookie security flags |
| APO020 | high | Literal privileged service-role credential |
| APO021 | high | Modeled input reaching selected NoSQL query sinks |
| APO022 | high | Code-executing agent tool construction |

Use `apollyon explain APO013` (or any registered ID) for a concrete pattern and
safer approach. [Coverage details and limits](AUDIT_UPGRADE.md) apply to every
rule. Automatic severity demotion based only on a test filename is not applied.
