"""Source and PyInstaller service entrypoint; explicit allowlist for worker modes."""
from pathlib import Path
import runpy
import sys

if not getattr(sys, 'frozen', False):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if __name__ == '__main__':
    module = 'yukiwire.backend'
    if len(sys.argv) > 2 and sys.argv[1] == '--worker':
        module = sys.argv[2]
        sys.argv = [sys.argv[0]] + sys.argv[3:]
    if module not in ('yukiwire.backend', 'yukiwire.watchdog', 'yukiwire.recovery', 'yukiwire.browser'):
        raise SystemExit('Unsupported worker mode')
    runpy.run_module(module, run_name='__main__')
