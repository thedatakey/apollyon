# CLI golden outputs

The Phase 0 baselines were captured from the unmodified `d1dc52e6a200d35c2dc974bfd4e1234276313681`
binary, version 0.2.0, before Phase 0. No whitespace, paths, or JSON fields were
normalized. Each file includes the CLI's final newline.

From the repository root, for each format (`text`, `json`, `sarif`):

```sh
apollyon scan tests/fixtures/manual-project --format <format>
apollyon scan tests/fixtures/manual-project --exclude generated --format <format>
apollyon scan tests/fixtures/manual-project --include-snippets --format <format>
```

The three commands correspond to `manual.*`, `excluded.*`, and `snippets.*`.
Only the explicit snippets case includes the checked-in sample source.
The golden integration tests compare stdout byte for byte, require empty
stderr, and check exit status. `.gitattributes` preserves LF in both scanned
fixtures and snapshots on every platform.

Do not regenerate these automatically during tests. Future intentional output
changes require an explained snapshot diff and changelog entry. Tool version
changes also require deliberate updates. These samples lock fixture behavior;
they are not proof that every possible input behaves identically.

Phase 1 intentionally updates these snapshots with twelve registry entries,
finding fingerprints, and adoption/selection counters. Before updating, a
structural comparison removed only these new fields and the six new registry
entries and confirmed all previous JSON/SARIF content was identical. Text
outputs retain the original bytes followed by the new accounting line.

Phase 2 deliberately moves the structured snapshots to findings v2 and adds
the required engine, confidence, trace, and parser-coverage fields. A
structural comparison removed only those documented additions (and normalized
the text engine labels/coverage line) and confirmed that Phase 1 content stayed
identical.

Phase 3 intentionally updates only the machine-readable scope sentence so it
describes AST validation and explicit lexical fallback. Existing snippet bytes,
findings, counts, and ordering were preserved; no snapshots were regenerated.
