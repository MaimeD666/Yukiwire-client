"""Long local-proxy check with the saved profile; never changes Windows networking."""
import argparse
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.acceptance import Backend, PORTS, kill_owned_core, port_open, snapshot, wait_clean
from yukiwire.network import process_identity
from yukiwire.paths import RUNTIME, STATE
from yukiwire.storage import ProfileStore, atomic_write


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--minutes', type=float, default=10)
    args = parser.parse_args()
    if args.minutes < 1 or args.minutes > 120:
        parser.error('Use 1–120 minutes')
    if any(map(port_open, PORTS)) or (STATE / 'network-lease.dpapi').exists():
        raise RuntimeError('Close Yukiwire before the soak check')
    store = ProfileStore()
    profile = store.get(store.public()['selected'])['text']
    before = snapshot()
    backend = Backend()
    report = {'capture': 'local', 'minutes': args.minutes, 'probes': 0, 'https_failures': 0, 'restart_verified': False}
    try:
        backend.send(action='start', profile=profile, settings={'capture': 'local', 'preset': 'all'})
        core = backend.wait('started')
        deadline = time.monotonic() + args.minutes * 60
        crash_at = deadline - args.minutes * 30
        while time.monotonic() < deadline:
            if time.monotonic() > crash_at and not report['restart_verified']:
                kill_owned_core(core['pid'], process_identity(core['pid']))
                core = backend.wait('started', predicate=lambda item: item.get('reconnected'))
                report['restart_verified'] = True
            backend.send(action='probe')
            try:
                backend.wait('probe_result', timeout=22)
                report['probes'] += 1
            except TimeoutError:
                report['https_failures'] += 1
            print('Soak HTTPS checks:', report['probes'], 'failures:', report['https_failures'], flush=True)
            time.sleep(min(18, max(0, deadline-time.monotonic())))
        backend.send(action='stop')
        backend.wait('stopped')
    finally:
        backend.close()
        report['cleanup'] = wait_clean(before)
        report['passed'] = report['probes'] > 0 and not report['https_failures'] and report['restart_verified'] and all(report['cleanup'].values())
        atomic_write(RUNTIME / 'soak-report.json', json.dumps(report, indent=2).encode())
    print('Soak passed:', report['passed'])
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
