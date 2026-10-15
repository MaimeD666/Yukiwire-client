"""Production host must reject test switches before creating a window/backend."""
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.build_native import build


def verify():
    executable = build()
    for switch in ('--smoke', '--smoke-connected', '--integration', '--integration-crash', '--network-worker'):
        result = subprocess.run([str(executable), switch], timeout=5,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode != 2:
            raise RuntimeError('Production accepted a test switch: ' + switch)
    if 'Page.crash'.encode('utf-16-le') in executable.read_bytes():
        raise RuntimeError('Renderer crash hook remains in production')
    if 'Yukiwire.NetworkWorker'.encode() in executable.read_bytes():
        raise RuntimeError('Legacy elevated Python worker remains in production')
    print('Production test switches rejected; renderer crash hook excluded.')


if __name__ == '__main__':
    verify()
