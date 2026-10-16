import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'nt', 'Windows x64 WFP ABI')
class NetworkFilterTests(unittest.TestCase):
    def test_native_structures_match_windows_sdk_without_mutating_network(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'FilterHarness.exe'
            compiler = Path(os.environ['WINDIR']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
            subprocess.run([str(compiler), '/nologo', '/target:exe', '/platform:x64', '/out:' + str(target),
                            str(ROOT / 'native/NetworkFilter.cs'), str(ROOT / 'tests/NetworkFilterHarness.cs')],
                           check=True, capture_output=True)
            result = subprocess.run([str(target)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
