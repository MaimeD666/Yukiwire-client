"""Owned network leases. Never reset Windows networking or touch another VPN."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import uuid
import hashlib
import winreg
from contextlib import contextmanager

from .paths import ROOT, STATE, RUNTIME, PORTABLE
from .storage import SecureFile


class OptionValue(ctypes.Union):
    _fields_ = [('flags', wintypes.DWORD), ('text', ctypes.c_void_p), ('time', wintypes.FILETIME)]


class Option(ctypes.Structure):
    _fields_ = [('option', wintypes.DWORD), ('value', OptionValue)]


class OptionList(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('connection', wintypes.LPWSTR), ('count', wintypes.DWORD), ('error', wintypes.DWORD), ('options', ctypes.POINTER(Option))]


class WinInetProxy:
    def __init__(self):
        self.api = ctypes.WinDLL('wininet', use_last_error=True)
        for name in ('InternetQueryOptionW', 'InternetSetOptionW'):
            function = getattr(self.api, name)
            function.restype = wintypes.BOOL
        self.api.InternetQueryOptionW.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
        self.api.InternetSetOptionW.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel.GlobalFree.argtypes = [ctypes.c_void_p]

    def read(self):
        options = (Option * 4)()
        for index in range(4):
            options[index].option = index + 1
        request = OptionList(ctypes.sizeof(OptionList), None, 4, 0, options)
        size = wintypes.DWORD(ctypes.sizeof(request))
        if not self.api.InternetQueryOptionW(None, 75, ctypes.byref(request), ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return {'flags': int(options[0].value.flags), **{key: ctypes.wstring_at(options[i].value.text) if options[i].value.text else '' for i, key in enumerate(('server', 'bypass', 'pac'), 1)}}
        finally:
            for index in range(1, 4):
                if options[index].value.text:
                    self.kernel.GlobalFree(options[index].value.text)

    def write(self, state):
        options = (Option * 4)()
        options[0].option = 1
        options[0].value.flags = state['flags']
        buffers = []
        for index, key in enumerate(('server', 'bypass', 'pac'), 1):
            options[index].option = index + 1
            buffer = ctypes.create_unicode_buffer(state[key])
            buffers.append(buffer)
            options[index].value.text = ctypes.cast(buffer, ctypes.c_void_p)
        request = OptionList(ctypes.sizeof(OptionList), None, 4, 0, options)
        if not self.api.InternetSetOptionW(None, 75, ctypes.byref(request), ctypes.sizeof(request)):
            raise ctypes.WinError(ctypes.get_last_error())
        # Refresh WinINET clients after the per-connection transaction.
        self.api.InternetSetOptionW(None, 95, None, 0)
        self.api.InternetSetOptionW(None, 37, None, 0)


def process_command(module, *args):
    if getattr(sys, 'frozen', False):
        return [sys.executable, '--worker', module, *map(str, args)]
    return [sys.executable, str(ROOT / 'scripts' / 'worker.py'), '--worker', module, *map(str, args)]


def register_recovery(path, kind):
    from .startup import register
    register(path, process_command('yukiwire.recovery', '--journal', path), kind)


def unregister_recovery(path):
    from .startup import unregister
    unregister(path, process_command('yukiwire.recovery', '--journal', path))


def running_process_names():
    class Entry(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('usage', wintypes.DWORD), ('pid', wintypes.DWORD), ('heap', ctypes.c_size_t),
                    ('module', wintypes.DWORD), ('threads', wintypes.DWORD), ('parent', wintypes.DWORD), ('priority', wintypes.LONG),
                    ('flags', wintypes.DWORD), ('name', wintypes.WCHAR * 260)]
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    api.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    api.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    api.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    snapshot = api.CreateToolhelp32Snapshot(2, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry = Entry()
        entry.size = ctypes.sizeof(entry)
        if not api.Process32FirstW(snapshot, ctypes.byref(entry)):
            raise ctypes.WinError(ctypes.get_last_error())
        names = set()
        while True:
            names.add(entry.name.lower())
            if not api.Process32NextW(snapshot, ctypes.byref(entry)):
                if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES
                    raise ctypes.WinError(ctypes.get_last_error())
                break
        return names
    finally:
        api.CloseHandle(snapshot)


def conflicts(proxy=None):
    proxy = proxy or WinInetProxy()
    state = proxy.read()
    other_proxy = bool(state['flags'] & 2 and state['server'] and state['server'] != '127.0.0.1:11809') or bool(state['flags'] & 4 and state['pac'])
    other_tun, check_failed = False, False
    try:
        names = running_process_names()
        other_tun = bool(names & {'nekoray.exe', 'nekobox.exe', 'nekobox_core.exe', 'sing-box.exe',
                                 'mihomo.exe', 'clash.exe', 'clash-meta.exe', 'clash-verge.exe',
                                 'v2rayn.exe', 'hiddify.exe'})
    except Exception:
        check_failed = True
    try:
        from .windows_snapshot import foreign_capture_present
        other_tun = foreign_capture_present() or other_tun
    except Exception:
        check_failed = True
    # Fail closed for capture, but let the UI distinguish uncertainty from a detected VPN.
    return {'other_proxy': other_proxy, 'other_vpn': other_tun or check_failed, 'check_failed': check_failed}


class ProxyLease:
    def __init__(self, journal, adapter=None):
        self.journal = journal
        self.adapter = adapter or WinInetProxy()

    def prepare(self, owner, core):
        original = self.adapter.read()
        if original['flags'] & 2 and original['server'] or original['flags'] & 4 and original['pac']:
            raise ValueError('Уже включён другой системный прокси/PAC. Yukiwire не будет заменять его. Выберите локальный режим.')
        desired = {'flags': 1 | 2, 'server': '127.0.0.1:11809', 'bypass': '<local>;localhost;127.*;[::1]', 'pac': ''}
        record = {'version': 1, 'lease_id': uuid.uuid4().hex, 'kind': 'proxy', 'owner': owner, 'core': core, 'original': original, 'desired': desired, 'phase': 'prepared'}
        self.journal.write(record)  # Durable record before any OS mutation.
        return record

    def apply(self):
        record = self.journal.read()
        if self.adapter.read() != record['original']:
            raise ValueError('Прокси Windows изменился во время запуска. Изменения Yukiwire отменены.')
        self.adapter.write(record['desired'])
        record['phase'] = 'applied'
        self.journal.write(record)

    def recover(self):
        record = self.journal.read()
        if record is None:
            return {'restored': True, 'conflict': False}
        current = self.adapter.read()
        if current == record['desired']:
            self.adapter.write(record['original'])
            if self.adapter.read() != record['original']:
                raise RuntimeError('Windows ещё не подтвердила восстановление прокси.')
        elif current != record['original']:
            # Preserve a newer user/other-client change. The journal remains for review.
            return {'restored': False, 'conflict': True}
        self.journal.path.unlink(missing_ok=True)
        return {'restored': True, 'conflict': False}


class NetworkGuard:
    def __init__(self):
        self.journal = SecureFile(STATE / 'network-lease.dpapi')
        self.watcher = None
        self.kind = None
        self.lease_id = None

    def arm(self, kind, pid, tun=None):
        with journal_lock(self.journal.path):
            self._arm(kind, pid, tun)

    def _arm(self, kind, pid, tun=None):
        if self.journal.path.exists():
            raise ValueError('Есть незавершённое восстановление сети. Откройте настройки безопасности.')
        if kind == 'system':
            record = ProxyLease(self.journal).prepare(os.getpid(), pid)
        elif kind == 'tun':
            record = {'version': 1, 'lease_id': uuid.uuid4().hex, 'kind': 'tun', 'owner': os.getpid(), 'core': pid, **tun}
        else:
            return
        self.kind = kind
        self.lease_id = record['lease_id']
        record['owner_start'] = process_identity(os.getpid())
        record['core_start'] = process_identity(pid)
        if record['owner_start'] is None or record['core_start'] is None:
            raise ValueError('Не удалось установить владельцев подключения. Настройки сети не будут изменены.')
        self.journal.write(record)
        register_recovery(self.journal.path, kind)
        self.watcher = subprocess.Popen(process_command('yukiwire.watchdog', '--journal', self.journal.path), cwd=ROOT,
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
        ready = threading.Event()
        reply = []
        def read_ready():
            reply.append(self.watcher.stdout.readline())
            ready.set()
        threading.Thread(target=read_ready, daemon=True).start()
        if not ready.wait(5) or not reply or reply[0].strip() != b'READY':
            raise RuntimeError('Защита восстановления сети не запустилась. Настройки не будут применены.')

    def apply_proxy(self):
        if self.kind == 'system':
            with journal_lock(self.journal.path):
                record = self.journal.read()
                if not record or record.get('lease_id') != self.lease_id:
                    raise ValueError('Подключение уже завершено. Прокси Windows не будет изменён.')
                if process_identity(record['core']) != record['core_start']:
                    raise ValueError('Ядро уже завершено. Прокси Windows не будет изменён.')
                ProxyLease(self.journal).apply()

    def recover(self):
        result = recover_journal(self.journal, expected_id=self.lease_id, cleanup_empty=bool(self.lease_id))
        if self.watcher:
            # The watcher exits after journal removal; stop it only after recovery.
            try:
                self.watcher.wait(timeout=3)
            except subprocess.TimeoutExpired:
                if result.get('restored'):
                    self.watcher.terminate()
                    self.watcher.wait(timeout=3)
            if self.watcher.poll() is not None:
                self.watcher.stdout.close()
                self.watcher = None
        return result


@contextmanager
def journal_lock(path):
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    api.CreateMutexW.restype = wintypes.HANDLE
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    api.ReleaseMutex.argtypes = [wintypes.HANDLE]
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    suffix = hashlib.sha256(str(Path(path).resolve()).lower().encode()).hexdigest()[:24]
    handle = api.CreateMutexW(None, False, 'Local\\YukiwireRecovery-' + suffix)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    acquired = False
    try:
        acquired = api.WaitForSingleObject(handle, 5000) in (0, 128)
        if not acquired:
            raise RuntimeError('Восстановление уже выполняется другим процессом.')
        yield
    finally:
        if acquired:
            api.ReleaseMutex(handle)
        api.CloseHandle(handle)


def recover_journal(journal, expected_id=None, stale_only=False, cleanup_empty=False):
    with journal_lock(journal.path):
        record = journal.read()
        if record and expected_id is not None and record.get('lease_id') != expected_id:
            return {'restored': False, 'conflict': True, 'reason': 'different_lease'}
        if record and stale_only:
            identity = process_identity(record['owner'])
            # Older journals lack creation times: a live PID is ambiguous, so preserve it.
            if identity is not None and (not record.get('owner_start') or identity == record['owner_start']):
                return {'restored': False, 'conflict': True, 'reason': 'active_owner'}
        if record and record.get('kind') == 'tun' and not ctypes.windll.shell32.IsUserAnAdmin():
            # Let the normal UI delegate recovery to its dedicated elevated helper.
            return {'restored': False, 'conflict': False, 'requires_elevation': True}
        result = _recover_journal(journal)
        if result.get('restored') and (record or cleanup_empty):
            unregister_recovery(journal.path)
        return result


def _recover_journal(journal):
    record = journal.read()
    if record is None:
        return {'restored': True, 'conflict': False}
    if record.get('version') != 1:
        raise ValueError('Неизвестный журнал восстановления. Автоматическое изменение сети запрещено.')
    if record['kind'] == 'proxy':
        return ProxyLease(journal).recover()
    if record['kind'] == 'tun':
        import re
        if not re.fullmatch(r'Yukiwire-[0-9a-f]{12}', record.get('adapter', '')):
            raise ValueError('Неверная идентичность TUN в журнале.')
        script = RUNTIME / 'helpers' / 'recover-tun.ps1' if PORTABLE else ROOT / 'scripts' / 'recover-tun.ps1'
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(script),
                                 '-AdapterName', record['adapter'], '-Description', record['description']],
                                capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode != 0:
            raise RuntimeError('Не удалось убрать собственные маршруты TUN. Журнал сохранён для повторного восстановления.')
        journal.path.unlink(missing_ok=True)
        return {'restored': True, 'conflict': False}
    raise ValueError('Неизвестный тип журнала сети.')


def new_tun():
    token = uuid.uuid4().hex[:12]
    return {'adapter': 'Yukiwire-' + token, 'description': 'Yukiwire ' + token}


def inspect_tun(mode, identity=None):
    from .windows_snapshot import adapters, routes, foreign_snapshot
    if mode == 'Snapshot':
        return foreign_snapshot()
    entries = adapters()
    if mode == 'Preflight':
        return {'addresses': [value for item in entries for value in item['addresses']]}
    if mode != 'Ready' or not identity:
        raise ValueError('Неверная проверка TUN.')
    matches = [item for item in entries if item['name'] == identity['adapter']]
    if not matches:
        return {'ready': False}
    if len(matches) != 1 or matches[0]['description'] != identity['description'] + ' Tunnel':
        raise ValueError('Идентичность адаптера TUN не совпадает.')
    adapter = matches[0]
    indexes = {adapter['index'], adapter['index6']} - {0}
    found = {item['prefix'] for item in routes() if item['index'] in indexes and
             item['metric'] == 0 and item['next_hop'] in ('0.0.0.0', '::')}
    required = {'0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1'}
    return {'ready': adapter['up'] and required.issubset(found) and
            {'172.29.250.1/30', 'fd72:756b:6977::1/126'}.issubset(adapter['addresses']) and
            adapter['dns'] == ['172.29.250.2']}


def tun_preflight():
    import ipaddress
    reserved = [ipaddress.ip_network('172.29.250.0/30'), ipaddress.ip_network('fd72:756b:6977::/126')]
    for value in inspect_tun('Preflight')['addresses']:
        network = ipaddress.ip_network(value, strict=False)
        if any(network.version == item.version and network.overlaps(item) for item in reserved):
            raise ValueError('Подсеть Yukiwire TUN занята существующим адаптером. Изменения сети отменены.')


def tun_ready(identity):
    return bool(inspect_tun('Ready', identity)['ready'])


def add_tun(config, identity):
    primary = next((o for o in config['outbounds'] if o['protocol'] not in ('freedom', 'blackhole', 'dns', 'loopback')), None)
    if not primary or not primary.get('tag'):
        raise ValueError('Для TUN нужен основной outbound с тегом.')
    config['dns'] = {'servers': ['https://1.1.1.1/dns-query'], 'tag': 'yukiwire-dns', 'queryStrategy': 'UseIP'}
    config['outbounds'].append({'tag': 'yukiwire-dns-out', 'protocol': 'dns'})
    config['routing']['rules'][0:0] = [
        {'type': 'field', 'inboundTag': ['yukiwire-dns'], 'outboundTag': primary['tag']},
        {'type': 'field', 'inboundTag': ['yukiwire-tun'], 'port': '53', 'outboundTag': 'yukiwire-dns-out'}
    ]
    config['inbounds'].append({'tag': 'yukiwire-tun', 'protocol': 'tun', 'settings': {
        'name': identity['adapter'], 'desc': identity['description'], 'mtu': 1500,
        'gateway': ['172.29.250.1/30', 'fd72:756b:6977::1/126'], 'dns': ['172.29.250.2'],
        'autoSystemRoutingTable': ['0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1'],
        'autoOutboundsInterface': 'auto', 'autoSystemWfpBlockLeak': ['dns', 'misconfigtun']},
        'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': True}})
    return config


def process_identity(pid):
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = api.OpenProcess(0x1000 | 0x100000, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:  # ERROR_INVALID_PARAMETER: PID no longer exists.
            return None
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        state = api.WaitForSingleObject(handle, 0)
        if state == 0:
            return None
        if state != 258:
            raise ctypes.WinError(ctypes.get_last_error())
        values = [wintypes.FILETIME() for _ in range(4)]
        if not api.GetProcessTimes(handle, *(ctypes.byref(value) for value in values)):
            raise ctypes.WinError(ctypes.get_last_error())
        return (values[0].dwHighDateTime << 32) | values[0].dwLowDateTime
    finally:
        api.CloseHandle(handle)


def recover_stale():
    journal = SecureFile(STATE / 'network-lease.dpapi')
    # Read and check under the same mutex as recovery, so a new lease cannot race us.
    return recover_journal(journal, stale_only=True)
