import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('distribution', ROOT / 'scripts/prepare_distribution.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class DistributionTests(unittest.TestCase):
    def test_native_packages_and_formula_require_verified_archives(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / 'binary'
            binary.write_bytes(b'inert test binary')
            artifacts = root / 'artifacts'
            for platform, target in module.TARGETS.items():
                subprocess.run([sys.executable, str(ROOT/'scripts/package_release.py'), '--binary', str(binary), '--target', target, '--version', '9.9.9', '--format', 'zip' if platform.startswith('win') else 'tar.gz', '--source-date-epoch', '1700000000', '--output-directory', str(artifacts)], check=True, stdout=subprocess.DEVNULL)
            subprocess.run([sys.executable, str(ROOT/'scripts/create_checksums.py'), str(artifacts)], check=True)
            output = root/'packages'
            module.prepare(artifacts, '9.9.9', output)
            package = json.loads((output/'apollyon/package.json').read_text())
            self.assertEqual(package['version'], '9.9.9')
            self.assertEqual(len(package['optionalDependencies']), 4)
            self.assertNotIn('scripts', package)
            self.assertIn('sha256', (output/'apollyon.rb').read_text())
            archive = next(artifacts.glob('*.tar.gz'))
            archive.write_bytes(b'tampered')
            with self.assertRaises(ValueError):
                module.prepare(artifacts, '9.9.9', root/'bad')
            self.assertFalse((root/'bad').exists())

if __name__ == '__main__':
    unittest.main()
