"""Normal-user client of the installed native network helper; no elevated Python."""
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import os
import queue
import struct
import threading
import uuid
from collections import defaultdict, deque

from .paths import RUNTIME
from .privilege import helper_directory, require_protected_helper

LIMIT = 4 * 1024 * 1024


def kernel_api():
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    api.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    api.GetProcessId.argtypes = [wintypes.HANDLE]
    api.GetProcessId.restype = wintypes.DWORD
    return api


def elevate(executable, arguments=()):
    """Explicit UAC only; retain the returned process identity for pipe binding."""
    import subprocess
    class ExecuteInfo(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('mask', wintypes.ULONG), ('window', wintypes.HWND),
                    ('verb', wintypes.LPCWSTR), ('file', wintypes.LPCWSTR), ('parameters', wintypes.LPCWSTR),
                    ('directory', wintypes.LPCWSTR), ('show', ctypes.c_int), ('instance', wintypes.HINSTANCE),
                    ('idlist', ctypes.c_void_p), ('class_name', wintypes.LPCWSTR), ('class_key', wintypes.HKEY),
                    ('hotkey', wintypes.DWORD), ('icon', wintypes.HANDLE), ('process', wintypes.HANDLE)]
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(ExecuteInfo)]
    shell.ShellExecuteExW.restype = wintypes.BOOL
    info = ExecuteInfo()
    info.size = ctypes.sizeof(info)
    info.mask = 0x40 | 0x100  # NOCLOSEPROCESS | NOASYNC
    info.verb, info.file = 'runas', str(executable)
    info.parameters = subprocess.list2cmdline(list(map(str, arguments)))
    info.directory, info.show = str(Path(executable).parent), 0
    if not shell.ShellExecuteExW(ctypes.byref(info)):
        if ctypes.get_last_error() == 1223:
            raise ValueError('Запрос Windows отменён. Подключение TUN не запущено.')
        raise OSError('Windows не запустила сетевой компонент.')
    if not info.process:
        raise OSError('Не удалось проверить процесс сетевого компонента.')
    return info.process


def installed_helper():
    folder = RUNTIME / 'network'
    manifest = json.loads((folder / 'component.json').read_text(encoding='utf-8'))
    identity = manifest['identity']
    target = helper_directory(identity) / 'Yukiwire.Network.exe'
    if not target.exists():
        installer = folder / 'Yukiwire.Network.Setup.exe'
        if hashlib.sha256(installer.read_bytes()).hexdigest() != manifest['installer_sha256']:
            raise ValueError('Установщик сетевого компонента повреждён. Переустановите Yukiwire.')
        handle = elevate(installer)
        api = kernel_api()
        try:
            if api.WaitForSingleObject(handle, 180000) != 0:
                raise ValueError('Установка сетевого компонента не завершена. Повторите подключение после установки.')
            code = wintypes.DWORD()
            if not api.GetExitCodeProcess(handle, ctypes.byref(code)) or code.value:
                raise ValueError('Не удалось установить защищённый сетевой компонент.')
        finally:
            api.CloseHandle(handle)
    require_protected_helper(target, identity)
    if hashlib.sha256(target.read_bytes()).hexdigest() != manifest['helper_sha256']:
        raise ValueError('Защищённый сетевой компонент повреждён. Переустановите Yukiwire.')
    return target, identity


class Pipe:
    def __init__(self):
        self.api = kernel_api()
        self.api.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR] + [wintypes.DWORD] * 6 + [ctypes.c_void_p]
        self.api.CreateNamedPipeW.restype = wintypes.HANDLE
        self.api.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        self.api.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
        self.api.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        self.api.GetNamedPipeClientProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
        for name in ('ReadFile', 'WriteFile'):
            getattr(self.api, name).argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                               ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        advapi = ctypes.WinDLL('advapi32', use_last_error=True)
        advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                                                               ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        self.api.LocalFree.argtypes = [ctypes.c_void_p]
        token = wintypes.HANDLE()
        if not advapi.OpenProcessToken(wintypes.HANDLE(-1), 8, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            size = wintypes.DWORD()
            advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            buffer = ctypes.create_string_buffer(size.value)
            if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            sid = ctypes.c_void_p()
            if not advapi.ConvertSidToStringSidW(ctypes.c_void_p.from_buffer(buffer), ctypes.byref(sid)):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                current_sid = ctypes.wstring_at(sid)
            finally:
                self.api.LocalFree(sid)
        finally:
            self.api.CloseHandle(token)
        descriptor = ctypes.c_void_p()
        acl = 'D:P(D;;GA;;;NU)(A;;GA;;;%s)(A;;GA;;;BA)(A;;GA;;;SY)' % current_sid
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(acl, 1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        class SecurityAttributes(ctypes.Structure):
            _fields_ = [('length', wintypes.DWORD), ('descriptor', ctypes.c_void_p), ('inherit', wintypes.BOOL)]
        security = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        self.name = 'YukiwireCore.' + uuid.uuid4().hex
        try:
            self.handle = self.api.CreateNamedPipeW('\\\\.\\pipe\\' + self.name, 3 | 0x80000, 8, 1, 65536, 65536, 0, ctypes.byref(security))
            if self.handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.api.LocalFree(descriptor)

    def connect(self, expected_pid):
        if not self.api.ConnectNamedPipe(self.handle, None) and ctypes.get_last_error() != 535:
            raise ctypes.WinError(ctypes.get_last_error())
        pid = wintypes.ULONG()
        if not self.api.GetNamedPipeClientProcessId(self.handle, ctypes.byref(pid)) or pid.value != expected_pid:
            raise ValueError('Не удалось проверить сетевой компонент.')

    def read(self, size):
        result = bytearray()
        while len(result) < size:
            buffer = ctypes.create_string_buffer(size - len(result))
            count = wintypes.DWORD()
            if not self.api.ReadFile(self.handle, buffer, len(buffer), ctypes.byref(count), None) or not count.value:
                raise EOFError('Network helper closed')
            result.extend(buffer.raw[:count.value])
        return bytes(result)

    def receive(self):
        size, = struct.unpack('<I', self.read(4))
        if not 2 <= size <= LIMIT:
            raise ValueError('Некорректный ответ сетевого компонента.')
        return json.loads(self.read(size))

    def send(self, value):
        data = json.dumps(value, ensure_ascii=False).encode('utf-8')
        if len(data) > LIMIT:
            raise ValueError('Конфигурация сетевого компонента слишком велика.')
        data = struct.pack('<I', len(data)) + data
        while data:
            count = wintypes.DWORD()
            if not self.api.WriteFile(self.handle, data, len(data), ctypes.byref(count), None) or not count.value:
                raise EOFError('Network helper closed')
            data = data[count.value:]

    def close(self):
        if self.handle:
            self.api.CancelIoEx(self.handle, None)
            self.api.DisconnectNamedPipe(self.handle)
            self.api.CloseHandle(self.handle)
            self.handle = None


class Broker:
    def __init__(self, cancel=None, component_identity=None):
        from .network import process_identity
        if component_identity is None:
            target, identity = installed_helper()
        else:
            identity = component_identity
            target = helper_directory(identity) / 'Yukiwire.Network.exe'
            require_protected_helper(target, identity)
            if not hashlib.sha256(target.read_bytes()).hexdigest().startswith(identity):
                raise ValueError('Версия компонента восстановления повреждена. Журнал сохранён.')
        self.identity = identity
        if cancel and cancel.is_set():
            raise ValueError('Подключение отменено.')
        self.pipe = Pipe()
        self.lock = threading.Lock()
        self.responses = queue.Queue()
        self.closed = threading.Event()
        self.exits = {}
        self.diagnostics = defaultdict(lambda: deque(maxlen=30))
        self.diagnostic_sink = None
        self.sequence = 0
        self.handle = None
        try:
            self.handle = elevate(target, (self.pipe.name, os.getpid(), process_identity(os.getpid())))
            pid = self.pipe.api.GetProcessId(self.handle)
            def receive():
                try:
                    self.pipe.connect(pid)
                    while True:
                        message = self.pipe.receive()
                        if message.get('event') == 'exited':
                            self.exits[message['serial']] = message
                            while len(self.exits) > 32:
                                del self.exits[min(self.exits)]
                        elif message.get('event') == 'diagnostic':
                            from .diagnostics import DebugTrace
                            record = DebugTrace.safe('core_log', message)
                            self.diagnostics[message['serial']].append(record)
                            while len(self.diagnostics) > 32:
                                del self.diagnostics[min(self.diagnostics)]
                            if self.diagnostic_sink:
                                try:
                                    self.diagnostic_sink(**record)
                                except Exception:
                                    pass  # Logging failure must not disconnect the helper.
                        else:
                            self.responses.put(message)
                except Exception:
                    self.closed.set()
                    self.responses.put(None)
            self.reader = threading.Thread(target=receive, daemon=True)
            self.reader.start()
            ready = self.responses.get(timeout=20)
            if not ready or ready.get('event') != 'ready' or ready.get('identity') != identity:
                raise ValueError('Сетевой компонент не подтвердил готовность.')
        except Exception:
            self.close()
            raise

    def request(self, action, **fields):
        with self.lock:
            if self.closed.is_set():
                raise ValueError('Связь с сетевым компонентом потеряна. Проверьте восстановление сети.')
            self.sequence += 1
            self.pipe.send(dict(fields, action=action, id=self.sequence))
            try:
                response = self.responses.get(timeout=60)
            except queue.Empty:
                self.close()
                raise ValueError('Сетевой компонент не ответил. Журнал восстановления сохранён.') from None
            if not response or response.get('id') != self.sequence:
                raise ValueError('Связь с сетевым компонентом потеряна. Журнал восстановления сохранён.')
            if not response.get('ok'):
                raise ValueError('Сетевой компонент отклонил конфигурацию или не завершил очистку. Проверьте совместимость профиля и восстановление сети.')
            return response.get('result')

    def close(self):
        self.closed.set()
        self.pipe.close()
        if self.handle:
            self.pipe.api.CloseHandle(self.handle)
            self.handle = None


class RemoteProcess:
    def __init__(self, broker, result):
        self.broker, self.pid, self.serial = broker, result['pid'], result['serial']
        self.started = result['core_start']
        self.returncode = None

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        event = self.broker.exits.get(self.serial)
        if event:
            self.returncode = event['code']
        elif self.broker.closed.is_set():
            from .network import process_identity
            if process_identity(self.pid) != self.started:
                self.returncode = 1
        return self.returncode

    def terminate(self):
        # submit(stop) must remain responsive even while Windows cleans TUN.
        def stop():
            try:
                self.broker.request('stop', serial=self.serial)
                self.returncode = 0
            except Exception:
                pass  # Session.stop owns reporting and retaining the recovery lease.
        threading.Thread(target=stop, daemon=True).start()


class ElevatedCore:
    def __init__(self, broker, config, identity, before_resume, protection=None):
        self.broker = broker
        self.process = None
        result = broker.request('prepare', config=json.dumps(config, ensure_ascii=False), assets=str(RUNTIME), local=identity is None)
        self.process = RemoteProcess(broker, result)
        if identity is not None:
            identity.update(adapter=result['adapter'], description=result['description'], protected_helper=True,
                            helper_id=broker.identity)
        try:
            before_resume(self.process.pid)
            if protection is not None:
                protection.arm(broker, self.process.serial)
            broker.request('start', serial=self.process.serial)
        except Exception:
            self.close()
            raise

    def permit_tun(self):
        if not self.broker.request('permit_tun', serial=self.process.serial):
            raise ValueError('Не подтверждён защищённый маршрут TUN.')

    def close(self):
        if not self.broker.closed.is_set():
            self.broker.request('stop', serial=self.process.serial)
            self.process.returncode = 0
        elif self.process.poll() is None:
            raise RuntimeError('Не подтверждена остановка сетевого ядра. Журнал сохранён.')

    def diagnostics(self):
        labels = {'tls': 'TLS: ошибка рукопожатия или проверки сертификата.', 'dns': 'DNS: ошибка разрешения имени.',
                  'timeout': 'Сервер не ответил вовремя.', 'refused': 'Соединение отклонено.',
                  'permission': 'Windows запретила сетевую операцию.', 'reset': 'Соединение сброшено.',
                  'config': 'Ошибка конфигурации ядра.', 'transport': 'Ошибка транспорта.',
                  'connection': 'Ошибка подключения.'}
        return list(dict.fromkeys(labels[item['category']] for item in self.broker.diagnostics[self.process.serial]
                                  if item.get('category') in labels and item.get('level') in ('warning', 'error')))[-5:]
