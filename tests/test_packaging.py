import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('portable_builder', ROOT / 'scripts' / 'build_portable.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class PackagingTests(unittest.TestCase):
    def test_private_state_beside_assets_is_never_added_to_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public = root / 'public.txt'
            public.write_text('public')
            (root / 'profiles.dpapi').write_bytes(b'private sentinel')
            archive = root / 'preview.zip'
            builder.write_archive(archive, {'README.md': public}, {'version': 'test'})
            with zipfile.ZipFile(archive) as zip_file:
                self.assertEqual(set(zip_file.namelist()), {'Yukiwire/README.md', 'Yukiwire/portable.json', 'Yukiwire/SHA256SUMS.json'})
                self.assertNotIn(b'private sentinel', b''.join(zip_file.read(name) for name in zip_file.namelist()))

    def test_stdlib_collection_excludes_installed_packages_and_tk(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('Lib/encodings/utf_8.py', 'Lib/site-packages/private.py', 'Lib/tkinter/__init__.py',
                         'Lib/test/test_ssl.py', 'Lib/idlelib/main.py', 'Lib/turtle.py'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('# fixture')
            self.assertEqual([name for name, _ in builder.library_files(root)], ['encodings/utf_8.py'])

    def test_distribution_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'public.txt'
            source.write_text('public')
            with self.assertRaises(ValueError):
                builder.write_archive(root / 'bad.zip', {'../private.txt': source}, {})
