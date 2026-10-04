"""Actual helper IPC failure cleanup, with a public fixture in local mode only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from build_native import build
from scripts.acceptance import PORTS, port_open, snapshot, wait_clean, kill_owned_core
from yukiwire.network import process_identity


def main():
    if any(map(port_open, PORTS)):
        raise RuntimeError('Close Yukiwire before testing IPC crash cleanup')
    executable = build()
    fixture = ROOT / 'runtime' / 'public-native-fixture.txt'
    fixture.write_text('vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls')
    ready = executable.parent / 'native-crash-ready.json'
    embedded = ROOT / 'runtime' / 'embedded-python' / 'python.exe'
    env = dict(os.environ, YUKIWIRE_ROOT=str(ROOT), YUKIWIRE_PYTHON=str(embedded) if embedded.is_file() else sys.executable)
    before = snapshot()
    reports = []
    for target in ('host', 'helper'):
        ready.unlink(missing_ok=True)
        host = subprocess.Popen([str(executable), '--integration-worker-crash', str(fixture)],
                                cwd=ROOT, env=env, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            deadline = time.monotonic() + 30
            while not ready.is_file() and time.monotonic() < deadline and host.poll() is None:
                time.sleep(.1)
            assert ready.is_file(), 'Owned helper did not start the test core'
            details = json.loads(ready.read_text())
            assert details['host_pid'] == host.pid
            core_identity = process_identity(details['core_pid'])
            assert core_identity is not None
            if target == 'host':
                host.kill()  # This Popen handle identifies only the host created above.
                host.wait(timeout=5)
            else:
                # The PID came from this host's Process.Start handle, not a process-name search.
                helper_identity = process_identity(details['worker_pid'])
                assert helper_identity is not None
                kill_owned_core(details['worker_pid'], helper_identity)
            cleanup = wait_clean(before)
            assert all(cleanup.values()), cleanup
            assert process_identity(details['core_pid']) != core_identity, 'Owned core survived IPC owner death'
            reports.append({'target': target, 'cleanup': cleanup, 'owned_core_closed': True})
            print(f'Actual {target} death: IPC EOF, owned core closed, Windows/Nekoray unchanged: passed')
        finally:
            if host.poll() is None:
                host.kill()
                host.wait(timeout=5)
            assert all(wait_clean(before).values()), 'Final IPC test cleanup incomplete'
    (ROOT / 'runtime' / 'helper-crash-report.json').write_text(json.dumps(reports, indent=2))


if __name__ == '__main__':
    main()
