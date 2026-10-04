"""Windows acceptance checks. Default is read-only; crashes target this test's children."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import ctypes
from ctypes import wintypes
import hashlib
import http.client
import json
import os
from pathlib import Path
import queue
import socket
import ssl
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from yukiwire.health import check_connection
from yukiwire.network import (WinInetProxy, conflicts, inspect_tun, process_command,
                              process_identity, recover_stale, tun_preflight)
from yukiwire.paths import CORE, ROOT, RUNTIME, STATE
from yukiwire.routing import DEFAULTS
from yukiwire.storage import ProfileStore, atomic_write
from yukiwire.windows_snapshot import foreign_snapshot

PORTS = (11808, 11809, 11811, 11812)


class AcceptanceError(ValueError):
    pass


def port_open(port):
    with socket.socket() as connection:
        connection.settimeout(.2)
        return connection.connect_ex(('127.0.0.1', port)) == 0


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def snapshot():
    return {'proxy': digest(WinInetProxy().read()), 'foreign_interfaces': digest(foreign_snapshot())}


def wait_clean(before, timeout=25):
    deadline = time.monotonic() + timeout
    stable = 0
    while time.monotonic() < deadline:
        clean = not (STATE / 'network-lease.dpapi').exists() and not any(map(port_open, PORTS))
        if clean:
            after = snapshot()
            if before == after:
                stable += 1
                if stable >= 2:
                    return {'ports_closed': True, 'journal_removed': True,
                            'proxy_restored': True, 'foreign_interfaces_unchanged': True}
            else:
                stable = 0
        time.sleep(.25)
    return {'ports_closed': not any(map(port_open, PORTS)),
            'journal_removed': not (STATE / 'network-lease.dpapi').exists(),
            'proxy_restored': before['proxy'] == digest(WinInetProxy().read()),
            'foreign_interfaces_unchanged': before['foreign_interfaces'] == digest(foreign_snapshot())}


class Backend:
    def __init__(self):
        environment = dict(os.environ, PYTHONIOENCODING='utf-8', YUKIWIRE_TEST_SESSION='1')
        self.process = subprocess.Popen(process_command('yukiwire.backend'), cwd=ROOT,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        text=True, encoding='utf-8', env=environment,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
        self.events = queue.Queue()
        def read():
            try:
                for line in self.process.stdout:
                    self.events.put(json.loads(line))
            finally:
                self.events.put({'event': '_eof'})
        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()
        try:
            self.wait('ready', timeout=30)
        except Exception:
            self.close()
            raise

    def send(self, **request):
        self.process.stdin.write(json.dumps(request) + '\n')
        self.process.stdin.flush()

    def wait(self, name, timeout=80, predicate=None):
        deadline = time.monotonic() + timeout
        while True:
            try:
                value = self.events.get(timeout=max(.01, deadline - time.monotonic()))
            except queue.Empty:
                raise TimeoutError('Test backend event timeout') from None
            if value['event'] == '_eof':
                raise RuntimeError('Test backend exited')
            if value['event'] == 'error' and value.get('operation') in ('start', '_restart', 'stop'):
                raise RuntimeError('Test backend operation failed')
            if value['event'] == name and (predicate is None or predicate(value)):
                return value
            if time.monotonic() >= deadline:
                raise TimeoutError('Test backend event timeout')

    def close(self):
        if self.process.poll() is None:
            try:
                self.send(action='quit')
                self.process.wait(timeout=12)
            except (OSError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        self.process.stdin.close()
        self.process.stdout.close()


def kill_owned_core(pid, identity):
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    api.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = api.OpenProcess(1 | 0x1000, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        times = [wintypes.FILETIME() for _ in range(4)]
        if not api.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
            raise ctypes.WinError(ctypes.get_last_error())
        if ((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime) != identity:
            raise RuntimeError('Owned core identity no longer matches')
        if not api.TerminateProcess(handle, 99):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        api.CloseHandle(handle)


def tun_transport():
    # No explicit HTTP/SOCKS proxy: the Windows route must carry this socket.
    connection = http.client.HTTPSConnection('www.cloudflare.com', timeout=12, context=ssl.create_default_context())
    try:
        connection.request('GET', '/cdn-cgi/trace', headers={'Connection': 'close'})
        response = connection.getresponse()
        response.read(8192)  # Discard IP and body.
        return {'tls_verified': True, 'http_status': response.status, 'explicit_proxy': False}
    finally:
        connection.close()


def exercise(profile, capture, before):
    checks = {}
    backend = None
    settings = dict(DEFAULTS, capture=capture, preset='all', auto_reconnect=True)
    try:
        backend = Backend()
        print('1/4: подключение и проверка HTTPS', flush=True)
        backend.send(action='start', profile=profile, settings=settings)
        started = backend.wait('started')
        checks['real_core_start'] = True
        identity = process_identity(started['pid'])
        if capture == 'tun':
            with ThreadPoolExecutor(max_workers=2) as pool:
                sites = pool.submit(check_connection)
                socket_check = pool.submit(tun_transport)
                checks['sites'] = sites.result()
                checks['tun_socket'] = socket_check.result()
        else:
            checks['sites'] = check_connection()
        if capture == 'system':
            checks['system_proxy_applied'] = WinInetProxy().read()['server'] == '127.0.0.1:11809'
        print('2/4: авария собственного ядра и автоподключение', flush=True)
        kill_owned_core(started['pid'], identity)
        restarted = backend.wait('started', predicate=lambda item: item.get('reconnected') is True)
        checks['core_crash_auto_reconnected'] = restarted['pid'] != started['pid']
        backend.send(action='stop')
        backend.wait('stopped', timeout=35)
        checks['normal_stop'] = wait_clean(before)
        if not all(checks['normal_stop'].values()):
            raise RuntimeError('Normal stop recovery incomplete')
        print('3/4: новый запуск и авария собственного сервиса', flush=True)
        backend.send(action='start', profile=profile, settings=settings)
        backend.wait('started')
        backend.process.kill()
        backend.process.wait(timeout=5)
        checks['owner_crash'] = wait_clean(before)
        if not all(checks['owner_crash'].values()):
            raise RuntimeError('Crash recovery incomplete; do not start another capture')
        backend.close()
        backend = Backend()
        print('4/4: запуск после аварии, остановка и очистка', flush=True)
        backend.send(action='start', profile=profile, settings=settings)
        backend.wait('started')
        checks['restart_after_owner_crash'] = True
        backend.send(action='stop')
        backend.wait('stopped', timeout=35)
    except Exception as exc:
        checks['failure_type'] = type(exc).__name__  # No raw exception/profile/server.
    finally:
        if backend:
            backend.close()
        checks['final_cleanup'] = wait_clean(before)
    return checks


def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    parser = argparse.ArgumentParser()
    parser.add_argument('--exercise', action='store_true', help='Actually run connection/crash/reconnect checks')
    parser.add_argument('--capture', choices=('local', 'system', 'tun'), default='local')
    parser.add_argument('--allow-network-changes', action='store_true', help='Explicitly permit owned Windows proxy/TUN changes')
    parser.add_argument('--profile', type=Path, help='Private link or JSON file; otherwise use selected encrypted profile')
    args = parser.parse_args()
    if args.exercise and args.capture != 'local' and not args.allow_network_changes:
        parser.error('system/tun exercise requires --allow-network-changes')
    report = {'version': '0.4', 'capture': args.capture, 'exercise_requested': args.exercise,
              'context': 'Standalone only when other_vpn and other_proxy are false', 'preflight': {}, 'checks': {}}
    preflight = report['preflight']
    try:
        preflight.update(conflicts())
        preflight['admin'] = bool(ctypes.windll.shell32.IsUserAnAdmin())
        preflight['core_present'] = CORE.is_file()
        preflight['wintun_present'] = (CORE.parent / 'wintun.dll').is_file()
        preflight['ports_free'] = not any(map(port_open, PORTS))
        preflight['journal_absent'] = not (STATE / 'network-lease.dpapi').exists()
        before = snapshot()
        preflight['network_snapshot_readable'] = True
        try:
            tun_preflight()
            preflight['tun_subnet_free'] = True
        except Exception as exc:
            preflight['tun_subnet_free'] = False
            preflight['tun_preflight_error_type'] = type(exc).__name__
        if args.exercise:
            if not preflight['core_present']:
                raise AcceptanceError('Нет ядра Xray. Сначала установите его.')
            if not preflight['ports_free']:
                raise AcceptanceError('Порты Yukiwire заняты. Отключите и закройте Yukiwire перед тестом.')
            if not preflight['journal_absent']:
                raise AcceptanceError('Есть незавершённый журнал сети. Сначала проверьте восстановление в Yukiwire.')
            if args.capture != 'local' and (preflight['other_proxy'] or preflight['other_vpn']):
                raise AcceptanceError('Работает другой VPN/прокси. Для совместной проверки выберите local; для самостоятельной завершите Nekoray по инструкции.')
            if args.capture == 'tun' and not all(preflight[name] for name in ('admin', 'wintun_present', 'tun_subnet_free')):
                raise AcceptanceError('Для TUN нужны администратор, Wintun и свободная служебная подсеть. Подробности в TESTING.md.')
            if args.profile:
                profile = args.profile.read_text(encoding='utf-8-sig')
            else:
                store = ProfileStore()
                selected = store.public()['selected']
                if not selected:
                    raise AcceptanceError('Сначала сохраните и выберите профиль в Yukiwire, затем закройте приложение и повторите тест.')
                profile = store.get(selected)['text']
            report['checks'] = exercise(profile, args.capture, before)
    except Exception as exc:
        report['failure_type'] = type(exc).__name__
        if isinstance(exc, AcceptanceError):
            report['failure_reason'] = str(exc)  # Static messages above, never raw OS/server errors.
    checks = report['checks']
    clean = checks.get('final_cleanup', {})
    lifecycle = ('failure_type' not in report and 'failure_type' not in checks and
                 checks.get('core_crash_auto_reconnected') is True and checks.get('restart_after_owner_crash') is True and
                 all(clean.values()) and all(checks.get('normal_stop', {}).values()) and all(checks.get('owner_crash', {}).values()))
    report['lifecycle_passed'] = bool(lifecycle)
    sites = checks.get('sites', {}).get('results', [])
    report['network_passed'] = bool(sites) and all(item.get('transport_ok') for item in sites)
    report['sites_accessible'] = bool(sites) and all(item.get('accessible') for item in sites)
    # A site's HTTP policy is separate from the client's transport/lifecycle result.
    report['passed'] = (lifecycle and report['network_passed']) if args.exercise else 'failure_type' not in report
    target = RUNTIME / 'acceptance-report.json'
    atomic_write(target, json.dumps(report, ensure_ascii=False, indent=2).encode())
    if report.get('failure_reason'):
        print(report['failure_reason'])
    if report.get('failure_type') and not report.get('failure_reason'):
        print('Данные или предварительная проверка недоступны (' + report['failure_type'] + '). Смотрите TESTING.md.')
    if args.exercise:
        print('Запуск, аварии и очистка: ' + ('ПРОЙДЕНЫ' if report['lifecycle_passed'] else 'НЕ ПРОЙДЕНЫ'))
        print('HTTPS-транспорт: ' + ('ПРОЙДЕН' if report['network_passed'] else 'НЕ ПОДТВЕРЖДЁН'))
        for result in sites:
            print('  ' + result['target'] + ': ' + result['message'])
        if checks.get('failure_type'):
            print('Этап подключения/восстановления прерван (' + checks['failure_type'] + '). Подробности в отчёте.')
    elif 'failure_type' not in report:
        print('Предварительная проверка выполнена. VPN не запускался; Windows не изменялась.')
        print('Другой VPN: ' + ('обнаружен' if preflight['other_vpn'] else 'не обнаружен'))
    print('Отчёт: ' + str(target))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
