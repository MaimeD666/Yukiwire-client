import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'nt', 'Windows IP Helper')
class NetworkCleanupTests(unittest.TestCase):
    def test_native_layouts_and_guard_without_network_changes(self):
        compiler = Path(os.environ['WINDIR']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / 'cleanup-test.exe'
            subprocess.run([str(compiler), '/nologo', '/platform:x64', '/out:' + str(target),
                            str(ROOT / 'native/NetworkCleanup.cs'), str(ROOT / 'tests/NetworkCleanupHarness.cs')], check=True)
            subprocess.run([str(target)], check=True, timeout=10)
