"""Desktop WebView2 launcher; network control runs in a separate process."""
import os
from pathlib import Path
import runpy
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    sys.path.insert(0, str(ROOT / 'scripts'))
    builder = runpy.run_path(str(ROOT / 'scripts' / 'build_native.py'))
    executable = builder['build']()
    environment = os.environ.copy()
    environment['YUKIWIRE_ROOT'] = str(ROOT)
    embedded = ROOT / 'runtime' / 'embedded-python' / 'python.exe'
    environment['YUKIWIRE_PYTHON'] = str(embedded) if embedded.is_file() else sys.executable
    return subprocess.call([str(executable)], cwd=ROOT, env=environment)


if __name__ == '__main__':
    raise SystemExit(main())
