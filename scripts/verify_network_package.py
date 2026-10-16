"""Run privileged acceptance against the exact ZIP from the release build job."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from verify_network_live import require_disposable_runner
from build_installer import payload

ROOT = Path(__file__).resolve().parents[1]


def verify(archive):
    require_disposable_runner()
    files, _ = payload(Path(archive))
    (ROOT / 'build/network').mkdir(parents=True, exist_ok=True)
    # Kept for the lifetime of the disposable runner: recovery can outlive a failed test.
    target = Path(tempfile.mkdtemp(prefix='network-package-', dir=ROOT / 'build')).resolve()
    assert target.is_relative_to((ROOT / 'build').resolve())
    for name, data in files.items():
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    environment = dict(os.environ, YUKIWIRE_ACCEPTANCE_BUNDLE=str(target))
    python = target / 'python/python.exe'
    for script, arguments, timeout in [('verify_network_component.py', ['--install'], 150),
                                       ('verify_network_live.py', [], 330)]:
        subprocess.run([str(python), '-u', str(ROOT / 'scripts' / script), *arguments],
                       env=environment, check=True, timeout=timeout)
    print('Exact release ZIP passed protected-helper and live network acceptance.')


if __name__ == '__main__':
    verify(sys.argv[1])
