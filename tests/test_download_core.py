import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile


spec = importlib.util.spec_from_file_location('download_core_test_target', Path(__file__).resolve().parents[1] / 'scripts/download_core.py')
downloader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(downloader)


class CoreDownloadTests(unittest.TestCase):
    def test_untrusted_archive_is_rejected_before_installation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            existing = root / 'runtime/core/xray.exe'
            existing.parent.mkdir(parents=True)
            existing.write_bytes(b'existing-core')
            with patch.object(downloader, 'ROOT', root), \
                 patch.object(downloader.urllib.request, 'urlopen', return_value=io.BytesIO(b'replaced-release')) as fetch:
                with self.assertRaisesRegex(RuntimeError, 'SHA256'):
                    downloader.main()
            self.assertEqual(existing.read_bytes(), b'existing-core')
            self.assertEqual(fetch.call_count, 1)  # No digest from the same compromised release.

    def test_reviewed_archive_installs_only_expected_files(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as bundle:
            bundle.writestr('xray.exe', b'fixture-core')
            bundle.writestr('geoip.dat', b'fixture-geoip')
            bundle.writestr('../outside.txt', b'not-an-allowed-asset')
        content = archive.getvalue()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(downloader, 'ROOT', root), \
                 patch.object(downloader, 'SHA256', hashlib.sha256(content).hexdigest()), \
                 patch.object(downloader.urllib.request, 'urlopen', side_effect=[io.BytesIO(content), io.BytesIO(b'license')]), \
                 patch('builtins.print'):
                downloader.main()
            self.assertEqual((root / 'runtime/core/xray.exe').read_bytes(), b'fixture-core')
            self.assertFalse((root / 'runtime/outside.txt').exists())


if __name__ == '__main__':
    unittest.main()
