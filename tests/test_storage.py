import json
from pathlib import Path
import tempfile
import unittest
from yukiwire.storage import ProfileStore, SecureFile


def test_cipher(data, decrypt=False):
    # A test double only, not a production fallback. Production always requires DPAPI.
    return bytes(byte ^ 0xB7 for byte in data)


class StorageTests(unittest.TestCase):
    def test_profile_roundtrip_and_public_list_has_no_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = ProfileStore(temporary, test_cipher)
            text = 'vless://private-credential@server.example:443'
            identity = store.save(text, 'Test', 'vless')
            self.assertEqual(store.get(identity)['text'], text)
            self.assertNotIn('private-credential', json.dumps(store.public()))
            self.assertNotIn(text.encode(), (Path(temporary) / 'profiles.dpapi').read_bytes())
            store.remove(identity)
            self.assertEqual(store.public()['profiles'], [])

    def test_failed_encryption_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'profiles.dpapi'
            secure = SecureFile(path, test_cipher)
            secure.write({'original': True})
            original = path.read_bytes()
            def failure(*args, **kwargs):
                raise OSError('DPAPI unavailable')
            secure.cipher = failure
            with self.assertRaises(OSError):
                secure.write({'new': True})
            self.assertEqual(path.read_bytes(), original)
