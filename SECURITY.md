# Security policy

## Supported versions

Apollyon is pre-alpha. The latest tagged prerelease and the default
branch receive security fixes. Older prereleases are unsupported after a newer
version is published; release notes and security advisories document upgrades.

## Reporting a vulnerability

Please do not disclose a suspected vulnerability in a public issue. Use the
repository's GitHub **Security → Report a vulnerability** flow or go directly
to <https://github.com/thedatakey/apollyon/security/advisories/new>.

Include the affected revision, impact, smallest safe reproduction, and any
known mitigations. Do not include credentials, third-party private data, or a
weaponized exploit. Good-faith defensive reports are welcome.

This policy covers Apollyon itself. It does not authorize testing unrelated
systems or code without the owner’s permission.

## Response expectations and rule reports

The maintainer aims to acknowledge private security reports within seven calendar
days, on a best-effort basis. This is not a guaranteed support SLA. Triage and
remediation timelines depend on impact and a reproducible case; coordinate any
disclosure date with the maintainer.

Scanner crashes, unsafe file handling, exposure of secrets in output, and
false negatives that bypass a documented detection guarantee are in scope.
Language-recognition and rule-language labels are not detection guarantees;
they describe bounded patterns documented in [RULES.md](docs/RULES.md).
Coverage requests and ordinary heuristic false positives/negatives may be
reported as normal issues when the report contains no sensitive source or
vulnerability details about another project. A missed candidate alone does
not establish an exploitable defect in Apollyon.
