import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from scripts.verify_release import verify
from yukiwire.version import VERSION, PACKAGE_NAME


class ReleaseTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        with zipfile.ZipFile(root / (PACKAGE_NAME + '.zip'), 'w') as archive:
            archive.writestr('Yukiwire/portable.json', json.dumps({'version': VERSION, 'tun_available': True}))
        (root / (PACKAGE_NAME + '-setup.exe')).write_bytes(b'public package fixture')
        (root / 'SHA256SUMS.txt').write_text(''.join(hashlib.sha256(file.read_bytes()).hexdigest() + '  ' + file.name + '\n' for file in root.iterdir()), encoding='ascii')
        return root

    def test_only_exact_verified_packages_can_be_published(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            verify(root)
            setup = root / (PACKAGE_NAME + '-setup.exe')
            setup.write_bytes(b'changed after check')
            with self.assertRaises(ValueError): verify(root)

    def test_upload_digest_must_match_tested_artifact(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as metadata:
            root = self.fixture(directory)
            release = {'draft': True, 'tag_name': 'v' + VERSION, 'assets': [
                {'name': file.name, 'size': file.stat().st_size, 'state': 'uploaded',
                 'digest': 'sha256:' + hashlib.sha256(file.read_bytes()).hexdigest()} for file in root.iterdir()]}
            uploaded = Path(metadata) / 'uploaded.json'
            uploaded.write_text(json.dumps(release))
            verify(root, uploaded)
            release['assets'][0]['digest'] = 'sha256:' + '0' * 64
            uploaded.write_text(json.dumps(release))
            with self.assertRaises(ValueError): verify(root, uploaded)

    def test_extra_artifacts_are_not_published(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            (root / 'private.json').write_bytes(b'public test marker')
            with self.assertRaises(ValueError): verify(root)
