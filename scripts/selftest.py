"""Real-core checks with Nekoray untouched. Profile and raw logs are never printed."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import winreg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from yukiwire.backend import Session


def snapshot_proxy():
    values = {}
    for name in ('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL'):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Internet Settings') as key:
                values[name] = winreg.QueryValueEx(key, name)
        except FileNotFoundError:
            values[name] = None
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def port_open(port):
    with socket.socket() as sock:
        sock.settimeout(.3)
        return sock.connect_ex(('127.0.0.1', port)) == 0


def wait_closed(port):
    for _ in range(30):
        if not port_open(port):
            return True
        time.sleep(.1)
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', type=Path, required=True, help='Private VLESS text or JSON file')
    args = parser.parse_args()
    profile = args.profile.read_text(encoding='utf-8-sig')
    before = snapshot_proxy()
    report = {'context': 'Nekoray TUN/system proxy may be active; no direct-connect claim', 'checks': {}}
    checks = report['checks']
    def probe_record():
        try:
            return session.probe()
        except Exception as exc:
            time.sleep(.3)
            return {'network_error': type(exc).__name__, 'diagnostics': session.core.diagnostics()}
    session = Session()
    files_before = set((ROOT / 'runtime').rglob('*.json'))
    try:
        session.start(profile)
        checks['real_core_start'] = True
        checks['https'] = probe_record()
        session.stop()
        checks['normal_stop_closes_port'] = wait_closed(11809)
        checks['profile_not_written_to_disk'] = set((ROOT / 'runtime').rglob('*.json')) == files_before
        try:
            session.probe()
            checks['probe_after_stop_rejected'] = False
        except ValueError:
            checks['probe_after_stop_rejected'] = True
        session.start(profile)
        checks['reconnect_https'] = probe_record()
        session.stop()
        # Kill a separate backend owned by this test, not the user's existing client.
        child = subprocess.Popen([sys.executable, '-u', '-m', 'yukiwire.backend'], cwd=ROOT,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, encoding='utf-8', creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            json.loads(child.stdout.readline())
            child.stdin.write(json.dumps({'action': 'start', 'profile': profile}) + '\n')
            child.stdin.flush()
            while True:
                started = json.loads(child.stdout.readline())
                if started['event'] == 'started':
                    break
                if started['event'] == 'error':
                    raise RuntimeError('Crash test backend could not start')
            pid = started['pid']
            api = ctypes.WinDLL('kernel32', use_last_error=True)
            api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            api.OpenProcess.restype = wintypes.HANDLE
            api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            api.CloseHandle.argtypes = [wintypes.HANDLE]
            handle = api.OpenProcess(0x100000, False, pid)
            if not handle:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                child.kill()
                child.wait(timeout=5)
                checks['owner_crash_kills_core'] = api.WaitForSingleObject(handle, 5000) == 0
            finally:
                api.CloseHandle(handle)
            checks['owner_crash_closes_port'] = wait_closed(11809)
            checks['crash_does_not_leave_profile'] = set((ROOT / 'runtime').rglob('*.json')) == files_before
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            child.stdin.close()
            child.stdout.close()
            child.stderr.close()
    except Exception as exc:
        time.sleep(.3)  # Let the log-reader classify the underlying core failure.
        checks['failure'] = type(exc).__name__
        if session.core:
            checks['diagnostics'] = session.core.diagnostics()
    finally:
        session.stop()
        checks['system_proxy_unchanged'] = before == snapshot_proxy()
    report['lifecycle_passed'] = 'failure' not in checks and all(value is not False for value in checks.values())
    report['passed'] = report['lifecycle_passed'] and 'network_error' not in checks.get('https', {}) and 'network_error' not in checks.get('reconnect_https', {})
    target = ROOT / 'runtime' / 'selftest-report.json'
    target.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps(report, indent=2, ensure_ascii=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
