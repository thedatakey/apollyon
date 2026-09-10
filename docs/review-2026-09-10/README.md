# Review follow-up — 2026-09-10

The review was checked against main commit `30b58cb`. Three detection gaps were
reproduced before changes, then fixed and checked with positive and negative
regressions. The original harness failed all three tests. The expanded Rust
suite now passes 118 tests. Fixtures are inert; test execution used the bounded
offline container described in each case record. An initial full-suite attempt
failed because the sandbox copy omitted the pinned corpus; the complete copy
passed. Strict Clippy passed.

| Review point | Disposition |
| --- | --- |
| 1. Credential declarations | Fixed AST eligibility; tested 19 declarations across all 13 languages and placeholder negatives. |
| 2. Java SQL | Added JDBC executeQuery/executeUpdate and request.getParameter source modeling; direct and propagated cases pass, bound values remain unflagged. |
| 3. Express sinks | Added bounded HTML concatenation in res.send/response.send. Redirects are not SSRF; open redirects remain outside current rules. |
| 4. Language parity | Narrowed executable rule labels, README, and security-policy wording; documented exact limitations. |
| 5. Dependency disclaimer | Already present on every JSON dependency report, including count/date/scope. Added a regression assertion; no extra stdout text to break JSON consumers. |
| 6. Action rebuilds | Added exact-source binary caching with pinned cache action. Source builds preserve the selected action revision; downloading v0.3.0 would omit unreleased fixes. Signed release installation remains a separate enhancement. |
| 7. Supply chain CI | Added pinned cargo-audit 0.22.2 against current RustSec advisories, with read-only permissions. Live result is recorded by CI, not the offline tests. |
| 8. Trace range | Replaced the ZZZ sentinel with the next-line exclusive bound. Current uppercase IDs were unaffected. |
| 9. Thread churn | Confirmed per-file thread creation. Deferred pool/scheduling changes pending representative many-small-file measurements and memory-bound verification. |

Case records: [credentials](case-1.json), [JDBC](case-2.json),
[HTML response](case-3.json). The golden SARIF changes update only rule-language
metadata; existing finding identities remain unchanged. Historical audit data
has not been rewritten to imply it measured this patch.
