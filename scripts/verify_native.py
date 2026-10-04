"""Verify real WebView2 → service → core lifecycle, including secure helper IPC."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from build_native import build
from scripts.acceptance import PORTS, port_open, snapshot, wait_clean


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--saved', action='store_true', help='Exercise the actual saved profile, local mode only')
    args = parser.parse_args()
    if any(map(port_open, PORTS)):
        raise RuntimeError('Close Yukiwire before native integration')
    executable = build()
    fixture = ROOT / 'runtime' / 'public-native-fixture.txt'
    fixture.write_text('vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls')
    embedded = ROOT / 'runtime' / 'embedded-python' / 'python.exe'
    environment = dict(os.environ, YUKIWIRE_ROOT=str(ROOT), YUKIWIRE_PYTHON=str(embedded) if embedded.is_file() else sys.executable)
    before = snapshot()
    reports = []
    modes = ('--integration', '--integration-worker', '--integration-renderer', '--integration-browser') if args.saved else ('--integration', '--integration-worker')
    for mode in modes:
        command = [str(executable), mode + '-saved'] if args.saved else [str(executable), mode, str(fixture)]
        process = subprocess.Popen(command, cwd=ROOT, env=environment, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            assert process.wait(timeout=50) == 0, 'Native integration process failed'
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        report = json.loads((executable.parent / 'native-integration-report.json').read_text())
        assert report['lifecycle_passed'], report['reason']
        if args.saved:
            assert report['network_response_received'], 'Real saved-profile HTTPS probe failed'
        if mode in ('--integration-renderer', '--integration-browser'):
            assert report['renderer_recovered_without_core_restart'], 'Renderer recovery interrupted the core'
        clean = wait_clean(before)
        assert all(clean.values()), clean
        reports.append({'mode': mode, **report, 'cleanup': clean})
        print(mode + ': actual UI click, service/core start, response, UI stop and network preservation passed')
    (ROOT / 'runtime' / 'native-checks-report.json').write_text(json.dumps(reports, indent=2))


if __name__ == '__main__':
    main()
