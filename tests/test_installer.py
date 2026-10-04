import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from build_installer import payload


class InstallerPayloadTests(unittest.TestCase):
    def archive(self, folder, extra=None, corrupt=False):
        files = {'Yukiwire.exe': b'app', 'python/python.exe': b'python', 'ui/assets/yukiwire.ico': b'icon',
                 'scripts/worker.py': b'worker',
                 'portable.json': json.dumps({'version': '0.4', 'tun_available': True}).encode()}
        files.update(extra or {})
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        if corrupt:
            files['Yukiwire.exe'] = b'tampered'
        path = Path(folder) / 'payload.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            for name, data in files.items():
                archive.writestr('Yukiwire/' + name, data)
            archive.writestr('Yukiwire/SHA256SUMS.json', json.dumps(hashes))
        return path

    def test_verified_payload_preserves_exact_files(self):
        with tempfile.TemporaryDirectory() as folder:
            files, metadata = payload(self.archive(folder))
        self.assertEqual(files['Yukiwire.exe'], b'app')
        self.assertEqual(metadata['version'], '0.4')

    def test_corruption_cannot_reach_installer_compiler(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                payload(self.archive(folder, corrupt=True))

    def test_private_and_unsafe_paths_are_rejected_even_when_manifest_lists_them(self):
        for name in ('state/profiles.dpapi', 'python/secret.DPAPI', 'ui/../../escape.exe',
                     'ui/..\\escape.exe', 'ui/C:escape.exe', 'ui/NUL', 'ui/ambiguous.',
                     'ui/{app}.txt', 'ui/"; Flags: external', 'ui/app.js\n[Run]'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as folder:
                with self.assertRaises(ValueError):
                    payload(self.archive(folder, {name: b'private'}))

    def test_case_collision_is_rejected_for_windows(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                payload(self.archive(folder, {'yukiwire.exe': b'different'}))

    def test_unlisted_files_cannot_enter_installer(self):
        with tempfile.TemporaryDirectory() as folder:
            path = self.archive(folder)
            with zipfile.ZipFile(path, 'a') as archive:
                archive.writestr('Yukiwire/ui/unlisted.txt', b'unlisted')
            with self.assertRaisesRegex(ValueError, 'manifest'):
                payload(path)
