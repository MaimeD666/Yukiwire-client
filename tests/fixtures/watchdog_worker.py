"""Test-only file adapter. Runs the production watchdog without changing Windows."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from yukiwire import network, watchdog
from yukiwire.storage import SecureFile, atomic_write


def test_cipher(data, decrypt=False):
    return data


class FileAdapter:
    def __init__(self):
        self.file = SecureFile(Path(sys.argv[2]).with_name('fake-os.json'), cipher=test_cipher)

    def read(self):
        return self.file.read()

    def write(self, value):
        self.file.write(value)


if __name__ == '__main__':
    network.WinInetProxy = FileAdapter
    network.unregister_recovery = lambda path: None
    watchdog.SecureFile = lambda path: SecureFile(path, cipher=test_cipher)
    watchdog.main()
