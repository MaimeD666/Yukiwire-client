"""User-bound DPAPI vault and durable replace-before-publish writes."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import tempfile
import threading
import uuid

from .paths import STATE


class Blob(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]


def _blob(data):
    buffer = ctypes.create_string_buffer(data)
    return Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer


def protect(data, decrypt=False):
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    source, source_buffer = _blob(data)
    entropy, entropy_buffer = _blob(b'Yukiwire vault v1')
    output = Blob()
    method = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    method.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    method.restype = wintypes.BOOL
    if not method(ctypes.byref(source), None, ctypes.byref(entropy), None, None, 1, ctypes.byref(output)):
        raise OSError(ctypes.get_last_error(), 'Windows DPAPI недоступен. Профили не будут сохранены открытым текстом.')
    try:
        return ctypes.string_at(output.data, output.size)
    finally:
        kernel.LocalFree(output.data)


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        if os.name == 'nt':
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
            if not kernel.MoveFileExW(temporary, str(path), 1 | 8):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class SecureFile:
    def __init__(self, path, cipher=protect):
        self.path = Path(path)
        self.cipher = cipher

    def read(self, default=None):
        if not self.path.exists():
            return default
        return json.loads(self.cipher(self.path.read_bytes(), decrypt=True).decode('utf-8'))

    def write(self, value):
        atomic_write(self.path, self.cipher(json.dumps(value, ensure_ascii=False).encode('utf-8')))


class ProfileStore:
    def __init__(self, directory=STATE, cipher=protect):
        self.file = SecureFile(Path(directory) / 'profiles.dpapi', cipher)
        self.lock = threading.RLock()

    def _read(self):
        result = self.file.read({'version': 1, 'profiles': [], 'selected': None})
        if result.get('version') != 1:
            raise ValueError('Версия библиотеки профилей не поддерживается.')
        return result

    def public(self):
        with self.lock:
            value = self._read()
            return {'profiles': [{k: p[k] for k in ('id', 'name', 'protocol')} for p in value['profiles']], 'selected': value['selected']}

    def save(self, text, name, protocol, profile_id=None):
        with self.lock:
            value = self._read()
            profile_id = profile_id or str(uuid.uuid4())
            entry = {'id': profile_id, 'name': name.strip()[:80] or 'Профиль', 'protocol': protocol, 'text': text}
            index = next((i for i, p in enumerate(value['profiles']) if p['id'] == profile_id), None)
            if index is None:
                value['profiles'].append(entry)
            else:
                value['profiles'][index] = entry
            value['selected'] = profile_id
            self.file.write(value)
            return profile_id

    def get(self, profile_id):
        with self.lock:
            entry = next((p for p in self._read()['profiles'] if p['id'] == profile_id), None)
            if entry is None:
                raise ValueError('Профиль не найден.')
            return dict(entry)

    def remove(self, profile_id):
        with self.lock:
            value = self._read()
            value['profiles'] = [p for p in value['profiles'] if p['id'] != profile_id]
            if value['selected'] == profile_id:
                value['selected'] = value['profiles'][0]['id'] if value['profiles'] else None
            self.file.write(value)

    def select(self, profile_id):
        with self.lock:
            self.get(profile_id)
            value = self._read()
            value['selected'] = profile_id
            self.file.write(value)
