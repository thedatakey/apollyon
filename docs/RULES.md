# Lexical rule boundaries

All twelve rules are review candidates. Token/call matching has no AST,
dataflow, exploitability, or framework guarantee. Comments and ordinary strings
are removed from the code view; the new rules also consume lexer-classified
literal metadata. Complex interpolation and grammar remain outside guarantees.

| Rule | Severity | Implemented Phase 1 boundary |
| --- | --- | --- |
| APO007 | high | Literal private-key header, bounded known credential prefixes, named credential assignment with a literal of at least 8 characters, or an ASCII non-whitespace literal of 32–512 bytes with Shannon entropy at least 4.5 bits/byte. |
| APO008 | medium | MD5, SHA1/SHA-1, DES/TripleDES/3DES, RC4, ECB identifiers, or matching algorithm literals on a line with a recognized crypto factory call. |
| APO009 | info | Non-cryptographic random calls in C/C++, JS/TS, Python, JVM, and PHP. Their use may be harmless. |
| APO010 | high | Literal TLS-disable flags, SSL_VERIFY_NONE, Node TLS environment disabling, same-line accepting HostnameVerifier, or empty same-line checkServerTrusted body. |
| APO011 | medium | SQL-keyword literal and a query API on the same line with concatenation/interpolation syntax. Parameterized calls without string construction are not matched. |
| APO012 | medium | Filesystem-call first argument containing a variable or expression rather than a fixed literal. This is a sink review boundary, not a traversal verdict. |

The full Phase 1 token lists live in `src/rules/patterns.rs`. Existing APO001–006
retain their original matcher behavior, including the C# 20-line formatter
window. Run `apollyon rules` for descriptions and language scope.

Secret evidence is never included for a line matched by APO007, even with
`--include-snippets`, and even if that rule is disabled or suppressed. Other
findings on that line are also redacted. This is conservative redaction of
recognized candidates, not a guarantee of detecting every possible secret.

Limits: named assignments and crypto factories are same-line associations;
SQL assembled on earlier lines is not followed; general custom trust-manager
bodies are not analyzed; path aliases/overloads cannot be resolved. Entropy
can match non-secret identifiers and cannot distinguish encryption keys from
other random data. Use suppression/config controls with explicit accounting,
then independently review candidates. No measured accuracy claim is made.
