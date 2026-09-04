import hashlib
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]


class ReleasePackagingTests(unittest.TestCase):
    def test_archives_are_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "apollyon"
            binary.write_bytes(b"test binary\n")
            hashes = []
            for index in range(2):
                output = root / f"run-{index}"
                for archive_format in ("tar.gz", "zip"):
                    subprocess.run([
                        sys.executable, str(ROOT / "scripts" / "package_release.py"),
                        "--binary", str(binary), "--target", "test-target", "--version", "9.9.9",
                        "--format", archive_format, "--source-date-epoch", "1700000000",
                        "--output-directory", str(output),
                    ], check=True, stdout=subprocess.DEVNULL)
                hashes.append([hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(output.iterdir())])
            self.assertEqual(hashes[0], hashes[1])

            package = "apollyon-v9.9.9-test-target"
            with tarfile.open(root / "run-0" / f"{package}.tar.gz") as archive:
                self.assertEqual(
                    sorted(archive.getnames()),
                    sorted([package, f"{package}/LICENSE", f"{package}/README.md", f"{package}/apollyon"]),
                )
                binary_info = archive.getmember(f"{package}/apollyon")
                self.assertEqual((binary_info.mode, binary_info.uid, binary_info.gid), (0o755, 0, 0))
                self.assertEqual(binary_info.mtime, 1700000000)

            with zipfile.ZipFile(root / "run-0" / f"{package}.zip") as archive:
                self.assertEqual(
                    sorted(archive.namelist()),
                    sorted([f"{package}/LICENSE", f"{package}/README.md", f"{package}/apollyon.exe"]),
                )
                binary_info = archive.getinfo(f"{package}/apollyon.exe")
                self.assertEqual(binary_info.external_attr >> 16, 0o755)

    def test_checksum_manifest_covers_exactly_four_sorted_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = ["apollyon-d.zip", "apollyon-a.tar.gz", "apollyon-c.zip", "apollyon-b.tar.gz"]
            for name in names:
                (root / name).write_bytes(name.encode("ascii"))
            subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "create_checksums.py"), str(root)],
                check=True,
            )
            lines = (root / "SHA256SUMS").read_text(encoding="ascii").splitlines()
            self.assertEqual([line.split("  ", 1)[1] for line in lines], sorted(names))
            for line in lines:
                digest, name = line.split("  ", 1)
                self.assertEqual(digest, hashlib.sha256((root / name).read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
