import ctypes
from ctypes import wintypes
import os
import subprocess
from collections import deque
import threading
import json


class BasicLimits(ctypes.Structure):
    _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
                ('flags', wintypes.DWORD), ('min_ws', ctypes.c_size_t), ('max_ws', ctypes.c_size_t),
                ('active', wintypes.DWORD), ('affinity', ctypes.c_size_t),
                ('priority', wintypes.DWORD), ('scheduling', wintypes.DWORD)]


class ExtendedLimits(ctypes.Structure):
    _fields_ = [('basic', BasicLimits), ('io', ctypes.c_uint64 * 6),
                ('process_memory', ctypes.c_size_t), ('job_memory', ctypes.c_size_t),
                ('peak_process', ctypes.c_size_t), ('peak_job', ctypes.c_size_t)]


class CoreProcess:
    """Windows kills the child when the owner's Job handle closes, even on a crash."""
    def __init__(self, executable, config, before_resume=None):
        if os.name != 'nt':
            raise RuntimeError('Эта сборка предназначена для Windows.')
        self.process = None
        self.handle = None
        self.messages = deque(maxlen=30)
        self.reader = None
        self.api = ctypes.WinDLL('kernel32', use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.api.CreateJobObjectW.restype = wintypes.HANDLE
        self.api.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise RuntimeError('Не удалось включить защиту процесса ядра.')
        try:
            self.process = subprocess.Popen([str(executable), 'run', '-format', 'json', '-c', 'stdin:'],
                                            cwd=executable.parent, stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            creationflags=subprocess.CREATE_NO_WINDOW | 0x00000004)  # CREATE_SUSPENDED
            if not self.api.AssignProcessToJobObject(self.handle, wintypes.HANDLE(int(self.process._handle))):
                raise RuntimeError('Windows не разрешила безопасный запуск ядра.')
            if before_resume:
                before_resume(self.process.pid)
            native = ctypes.WinDLL('ntdll')
            native.NtResumeProcess.argtypes = [wintypes.HANDLE]
            native.NtResumeProcess.restype = ctypes.c_long
            if native.NtResumeProcess(wintypes.HANDLE(int(self.process._handle))) != 0:
                raise RuntimeError('Не удалось запустить защищённый процесс ядра.')
            self.reader = threading.Thread(target=self._read, daemon=True)
            self.reader.start()
            self.process.stdin.write(json.dumps(config, ensure_ascii=False).encode('utf-8'))
            self.process.stdin.close()
        except Exception:
            self.close()
            raise

    def _read(self):
        for line in iter(self.process.stdout.readline, b''):
            text = line.decode('utf-8', errors='replace').strip()
            # Keep only a diagnostic category, never raw server/UUID/path data.
            lower = text.lower()
            if 'certificate' in lower or 'x509' in lower:
                self.messages.append('TLS: ошибка проверки сертификата сервера.')
            elif 'timeout' in lower or 'deadline' in lower:
                self.messages.append('Сервер не ответил за отведённое время.')
            elif 'refused' in lower:
                self.messages.append('Соединение отклонено сервером или локальным портом.')
            elif 'forbidden' in lower or 'access permissions' in lower or 'permission denied' in lower:
                self.messages.append('ОС или среда выполнения запретила сетевой доступ процесса.')
            elif 'connection reset' in lower:
                self.messages.append('Соединение сброшено удалённой стороной или сетевым фильтром.')
            elif 'failed to' in lower or '[error]' in lower:
                self.messages.append('Ошибка ядра при обработке соединения; проверьте транспорт и доступность сервера.')

    def diagnostics(self):
        return list(dict.fromkeys(self.messages))[-5:]

    def close(self):
        try:
            if self.process and self.process.poll() is None:
                try:
                    self.process.terminate()
                except OSError:
                    pass  # Exit races and termination failures must still close the job.
        finally:
            if self.handle:
                if not self.api.CloseHandle(self.handle):
                    raise ctypes.WinError(ctypes.get_last_error())
                self.handle = None
        try:
            if self.process:
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
        finally:
            if self.reader:
                self.reader.join(timeout=1)
            # Closing a buffered reader while a live child owns its pipe can block forever.
            if self.process and self.process.poll() is not None:
                for stream in (self.process.stdin, self.process.stdout):
                    if stream and not stream.closed:
                        try:
                            stream.close()
                        except OSError:
                            pass
