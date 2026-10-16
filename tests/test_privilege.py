import os
from pathlib import Path
import tempfile
import unittest
from yukiwire.privilege import protected_acl, helper_directory, require_protected_helper


@unittest.skipUnless(os.name == 'nt', 'Windows ACL boundary')
class PrivilegeTests(unittest.TestCase):
    def test_user_writable_executable_cannot_be_an_elevated_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'Yukiwire.Network.exe'
            file.write_bytes(b'public test fixture, not executable')
            self.assertFalse(protected_acl(file))
            with self.assertRaises(ValueError):
                require_protected_helper(file, 'a' * 32)

    def test_component_identity_cannot_escape_protected_directory(self):
        for identity in ('../elsewhere', 'a' * 32 + '/..', '', 'G' * 32):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                helper_directory(identity)
