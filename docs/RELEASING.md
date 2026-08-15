# Release Apollyon

Releases are immutable, tag-driven, and published as GitHub prereleases while
Apollyon remains pre-alpha. Never move or recreate a published version tag;
issue a new patch version for corrections.

## Repository settings

Before publishing, maintainers must:

- require the CI workflow on `main` and block force-pushes or branch deletion;
- protect `v*` tags from modification or deletion;
- enable immutable releases, private vulnerability reporting, secret scanning,
  push protection, Dependabot alerts, and security updates;
- keep Actions permissions read-only by default.

The release workflow grants `contents: write`, `attestations: write`,
`artifact-metadata: write`, and `id-token: write` only to the final publication
job. Every external action is pinned to a full commit SHA.

## Prepare

1. Update `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`, `CITATION.cff`, the Claude
   plugin manifest, README download links, and installation examples to the same
   semantic version.
2. Run the complete gate:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo build --release --locked
cargo +1.74.0 check --locked
python3 scripts/validate_agents.py
python3 scripts/validate_integrations.py
python3 scripts/validate_outputs.py target/debug/apollyon
python3 scripts/validate_release.py
```

3. Push `main` and wait for all required checks to pass.
4. Create an annotated or signed tag at that exact tested commit:

```sh
git tag -a v0.2.0 -m "Apollyon v0.2.0"
git push origin v0.2.0
```

## Automated publication

The tag workflow verifies tag, manifest, lockfile, changelog, tests, MSRV, and
agent contracts. It builds and smoke-tests four archives:

- Linux x86-64 using musl
- macOS Apple Silicon
- macOS Intel
- Windows x86-64

The final job verifies exactly four archives, creates `SHA256SUMS`, attaches
GitHub artifact attestations, and publishes an unsigned public prerelease.

## Verify the public release

Download every asset on its native system. Verify `SHA256SUMS`, the GitHub
attestation, `apollyon --version`, `apollyon rules`, and a JSON fixture scan.
Confirm that release notes state the pre-alpha and unsigned-binary boundaries.

If any check fails after publication, do not replace the release assets or move
the tag. Document the problem and issue the next patch release.
