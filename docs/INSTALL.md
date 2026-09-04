# Install Apollyon

Apollyon v0.3.0 is a public pre-alpha. Choose a checksummed release archive or
install the exact tagged source with Rust 1.85 or newer.

## Release archives

Download the matching archive and `SHA256SUMS` from the
[v0.3.0 release](https://github.com/thedatakey/apollyon/releases/tag/v0.3.0):

| System | Archive |
| --- | --- |
| Linux x86-64 | `apollyon-v0.3.0-x86_64-unknown-linux-musl.tar.gz` |
| macOS Apple Silicon | `apollyon-v0.3.0-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `apollyon-v0.3.0-x86_64-apple-darwin.tar.gz` |
| Windows x86-64 | `apollyon-v0.3.0-x86_64-pc-windows-msvc.zip` |

The release signs `SHA256SUMS` with a keyless Sigstore certificate and attaches
signed GitHub SLSA build provenance for each archive. macOS Gatekeeper or
Windows SmartScreen may still warn because the pre-alpha binaries are not
platform-notarized.

### Verify on Linux

```sh
set -euo pipefail
asset=apollyon-v0.3.0-x86_64-unknown-linux-musl.tar.gz
curl -fLO "https://github.com/thedatakey/apollyon/releases/download/v0.3.0/$asset"
curl -fLO "https://github.com/thedatakey/apollyon/releases/download/v0.3.0/SHA256SUMS"
grep " $asset$" SHA256SUMS | sha256sum --check
tar -xzf "$asset"
./apollyon-v0.3.0-x86_64-unknown-linux-musl/apollyon --version
```

Move the verified executable to a directory already on your `PATH`, such as
`$HOME/.local/bin`, if desired.

### Verify on macOS

Choose `aarch64-apple-darwin` for Apple Silicon or `x86_64-apple-darwin` for an
Intel Mac, then run:

```sh
set -euo pipefail
asset=apollyon-v0.3.0-aarch64-apple-darwin.tar.gz
curl -fLO "https://github.com/thedatakey/apollyon/releases/download/v0.3.0/$asset"
curl -fLO "https://github.com/thedatakey/apollyon/releases/download/v0.3.0/SHA256SUMS"
expected="$(grep " $asset$" SHA256SUMS | cut -d ' ' -f 1)"
actual="$(shasum -a 256 "$asset" | cut -d ' ' -f 1)"
test "$actual" = "$expected"
tar -xzf "$asset"
./apollyon-v0.3.0-aarch64-apple-darwin/apollyon --version
```

### Verify on Windows PowerShell

```powershell
$asset = "apollyon-v0.3.0-x86_64-pc-windows-msvc.zip"
$base = "https://github.com/thedatakey/apollyon/releases/download/v0.3.0"
Invoke-WebRequest "$base/$asset" -OutFile $asset
Invoke-WebRequest "$base/SHA256SUMS" -OutFile SHA256SUMS
$expected = ((Select-String -Path SHA256SUMS -Pattern " $asset$").Line -split " ")[0]
$actual = (Get-FileHash $asset -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "SHA-256 verification failed" }
Expand-Archive -LiteralPath $asset -DestinationPath .
& ".\apollyon-v0.3.0-x86_64-pc-windows-msvc\apollyon.exe" --version
```

## Verify build provenance

Release archives also receive GitHub artifact attestations. With GitHub CLI
installed, verify a downloaded archive against this repository:

```sh
gh attestation verify apollyon-v0.3.0-x86_64-unknown-linux-musl.tar.gz \
  --repo thedatakey/apollyon
```

The checksum detects corruption or substitution relative to the release
manifest. The attestation links the archive to the repository's GitHub Actions
build. Neither is a substitute for code review or platform notarization.

Verify the signed checksum manifest with Cosign 3.1.2:

```sh
curl -fLO https://github.com/thedatakey/apollyon/releases/download/v0.3.0/SHA256SUMS.sigstore.json
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/thedatakey/apollyon/.github/workflows/release.yml@refs/tags/v0[.]3[.]0$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

This signature authenticates the checksum manifest; checking the manifest then
binds each named archive to its recorded SHA-256 digest.

## Install from tagged source

```sh
cargo install --locked --git https://github.com/thedatakey/apollyon \
  --tag v0.3.0 apollyon
apollyon --version
```

For development:

```sh
git clone https://github.com/thedatakey/apollyon.git
cd apollyon
cargo install --locked --path .
```

The package is intentionally not published to crates.io yet. A plain
`cargo install apollyon` command is therefore not supported.

## First scan

```sh
apollyon scan /path/to/project
apollyon scan /path/to/project --format json --fail-on high
```

Exit `1` means a configured threshold was met. Exit `3` means the scan was
incomplete and must not be described as clean. Run `apollyon --help` and
`apollyon rules` for the complete command and rule registry.
