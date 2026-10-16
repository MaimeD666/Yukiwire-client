import json
from pathlib import Path
import tempfile
import unittest
from yukiwire.storage import ProfileStore, SecureFile


def test_cipher(data, decrypt=False):
    # A test double only, not a production fallback. Production always requires DPAPI.
    return bytes(byte ^ 0xB7 for byte in data)


class StorageTests(unittest.TestCase):
    def test_backup_merge_is_atomic_deduplicated_and_keeps_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = ProfileStore(temporary, test_cipher)
            selected = store.save('original-fixture', 'Existing', 'vless')
            backup = {'format': 'yukiwire-profiles', 'version': 1, 'profiles': [
                {'name': 'Duplicate', 'text': 'original-fixture'}, {'name': 'New', 'text': 'new-fixture'}]}
            self.assertEqual(store.import_profiles(backup, lambda text: 'vless'), 1)
            self.assertEqual(store.public()['selected'], selected)
            self.assertEqual(len(store.export_profiles()['profiles']), 2)
            previous = store.file.path.read_bytes()
            backup['profiles'].append({'text': 'invalid'})
            with self.assertRaises(ValueError):
                store.import_profiles(backup, lambda text: 'vless')
            self.assertEqual(store.file.path.read_bytes(), previous)

    def test_foreign_or_corrupt_dpapi_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'profiles.dpapi'
            path.write_bytes(b'foreign-file')
            def unavailable(*args, **kwargs):
                raise OSError('private OS detail')
            with self.assertRaisesRegex(ValueError, 'другом ПК') as error:
                SecureFile(path, unavailable).read()
            self.assertNotIn('private OS detail', str(error.exception))
            self.assertEqual(path.read_bytes(), b'foreign-file')

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
