#!/usr/bin/env python3
"""Generate npm native packages and a Homebrew formula from checked release archives."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    'linux-x64': 'x86_64-unknown-linux-musl',
    'darwin-arm64': 'aarch64-apple-darwin',
    'darwin-x64': 'x86_64-apple-darwin',
    'win32-x64': 'x86_64-pc-windows-msvc',
}

def prepare(artifacts: Path, version: str, output: Path) -> None:
    if not re.fullmatch(r'(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)', version):
        raise ValueError('expected a numeric release version')
    checksums = {}
    for line in (artifacts / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        name = name.lstrip('*')
        if not re.fullmatch('[0-9a-f]{64}', digest) or Path(name).name != name:
            raise ValueError('invalid checksum manifest')
        if name in checksums:
            raise ValueError('duplicate checksum entry')
        checksums[name] = digest
    planned = []
    for platform, target in TARGETS.items():
        stem = f'apollyon-v{version}-{target}'
        suffix = 'zip' if platform.startswith('win32') else 'tar.gz'
        filename = f'{stem}.{suffix}'
        path = artifacts / filename
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 100_000_000:
            raise ValueError(f'invalid archive: {filename}')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != checksums.get(filename):
            raise ValueError(f'checksum mismatch: {filename}')
        binary = 'apollyon.exe' if platform.startswith('win32') else 'apollyon'
        member = f'{stem}/{binary}'
        if suffix == 'zip':
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                info = archive.getinfo(member)
                if info.file_size > 100_000_000:
                    raise ValueError('binary size limit')
                contents = archive.read(info)
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
                info = archive.getmember(member)
                if not info.isfile() or info.size > 100_000_000:
                    raise ValueError('archive binary is not a bounded regular file')
                contents = archive.extractfile(info).read()
        planned.append((platform, binary, filename, contents))
    output.mkdir(parents=True, exist_ok=False)
    wrapper = output / 'apollyon'
    shutil.copytree(ROOT / 'distribution/npm', wrapper)
    manifest = json.loads((wrapper / 'package.json').read_text())
    manifest['version'] = version
    manifest['optionalDependencies'] = {f'apollyon-{p}': version for p in TARGETS}
    (wrapper / 'package.json').write_text(json.dumps(manifest, indent=2) + '\n')
    for platform, binary, filename, contents in planned:
        folder = output / f'apollyon-{platform}'
        (folder / 'bin').mkdir(parents=True)
        executable = folder / 'bin' / binary
        executable.write_bytes(contents)
        executable.chmod(0o755)
        os_name, cpu = platform.split('-')
        manifest = {'name': f'apollyon-{platform}', 'version': version, 'license': 'MIT',
                    'os': [os_name], 'cpu': [cpu], 'files': ['bin', 'LICENSE'],
                    'repository': 'https://github.com/thedatakey/apollyon'}
        (folder / 'package.json').write_text(json.dumps(manifest, indent=2) + '\n')
        shutil.copyfile(ROOT / 'LICENSE', folder / 'LICENSE')
    def stanza(target):
        name = f'apollyon-v{version}-{target}.tar.gz'
        return f'url "https://github.com/thedatakey/apollyon/releases/download/v{version}/{name}"\n      sha256 "{checksums[name]}"'
    formula = f'''class Apollyon < Formula
  desc "Bounded source security scanner with explicit coverage"
  homepage "https://github.com/thedatakey/apollyon"
  version "{version}"
  license "MIT"
  on_macos do
    if Hardware::CPU.arm?
      {stanza(TARGETS['darwin-arm64'])}
    else
      {stanza(TARGETS['darwin-x64'])}
    end
  end
  on_linux do
    on_intel do
      {stanza(TARGETS['linux-x64'])}
    end
  end
  def install
    bin.install "apollyon"
  end
  test do
    assert_match version.to_s, shell_output("#{{bin}}/apollyon --version")
  end
end
'''
    (output / 'apollyon.rb').write_text(formula)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    prepare(args.artifacts, args.version, args.output)
