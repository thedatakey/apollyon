# Publishing the reviewed 0.4.0 distribution

This is an **unreleased** distribution implementation. Package-manager install
commands are not advertised as available until publication succeeds.

1. Finish all source, platform, MSRV, output, and corpus checks before tagging.
2. Review a release tag on main. Existing release CI tests and independently
   rebuilds binaries on all four supported targets, signs archive checksums,
   and attaches provenance.
3. Release CI also runs `scripts/prepare_distribution.py` against those verified
   archives. Its `package-manager-distribution` artifact contains five npm
   tarballs, a Homebrew formula, signed checksums, and separate provenance.
4. Review and authenticate those artifacts. An authorized registry owner can
   publish the four `apollyon-{platform}` tarballs first, then the `apollyon`
   wrapper. Test `npx apollyon@0.4.0 scan <inert fixture>` in a clean environment
   without Rust. Publishing requires npm namespace ownership and authentication.
5. An authorized owner can run `cargo publish --locked` for the reviewed crate
   and commit the generated `apollyon.rb` into their Homebrew tap. These require
   registry/tap access. Cross-platform installation must pass before announcing.

Local fixture tests validate checksum rejection and package generation; they do
not substitute for registry publication or real cross-platform installation.
No registry credentials are stored in the repository, no automatic registry
publishing is enabled, and the scanner never installs scanned dependencies.
