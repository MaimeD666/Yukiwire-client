"""User-bound DPAPI vault and durable replace-before-publish writes."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import tempfile
import threading
import time
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
        try:
            return json.loads(self.cipher(self.path.read_bytes(), decrypt=True).decode('utf-8'))
        except (OSError, ValueError, UnicodeError) as exc:
            raise ValueError('Не удалось открыть защищённые данные Windows: файл повреждён или создан на другом ПК/под другой учётной записью. Исходный файл сохранён. Для переноса используйте экспорт профилей на исходном ПК.') from exc

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
            return {'profiles': [{k: p[k] for k in ('id', 'name', 'protocol')} for p in value['profiles']], 'selected': value['selected'],
                    'subscriptions': [{key: subscription[key] for key in ('id', 'name', 'updated')}
                                      for subscription in value.get('subscriptions', [])]}

    def subscription(self, identity):
        with self.lock:
            result = next((entry for entry in self._read().get('subscriptions', []) if entry['id'] == identity), None)
            if result is None:
                raise ValueError('Подписка не найдена.')
            return dict(result)

    def update_subscription(self, url, name, profiles, identity=None):
        from .subscriptions import validate_url
        validate_url(url)
        if not profiles:
            raise ValueError('Подписка пуста. Прежние профили сохранены.')
        with self.lock:
            value = self._read()
            subscriptions = value.setdefault('subscriptions', [])
            if identity is None:
                identity = next((entry['id'] for entry in subscriptions if entry['url'] == url), None)
            if identity is not None and not any(entry['id'] == identity for entry in subscriptions):
                raise ValueError('Подписка не найдена.')
            identity = identity or str(uuid.uuid4())
            old = [entry for entry in value['profiles'] if entry.get('subscription_id') == identity]
            ids = {entry['text']: entry['id'] for entry in old}
            selected = next((entry for entry in old if entry['id'] == value['selected']), None)
            new = [dict(entry, id=ids.get(entry['text'], str(uuid.uuid4())), subscription_id=identity) for entry in profiles]
            value['profiles'] = [entry for entry in value['profiles'] if entry.get('subscription_id') != identity] + new
            record = {'id': identity, 'url': url, 'name': str(name).strip()[:80] or 'Подписка', 'updated': int(time.time())}
            value['subscriptions'] = [entry for entry in subscriptions if entry['id'] != identity] + [record]
            if value['selected'] not in {entry['id'] for entry in value['profiles']}:
                same_name = next((entry for entry in new if selected and entry['name'] == selected['name']), None)
                value['selected'] = (same_name or new[0])['id']
            self.file.write(value)  # URL and entire profile revision share one DPAPI transaction.
            return identity

    def remove_subscription(self, identity):
        with self.lock:
            value = self._read()
            value['subscriptions'] = [entry for entry in value.get('subscriptions', []) if entry['id'] != identity]
            # Detach profiles instead of deleting working saved connections.
            for entry in value['profiles']:
                if entry.get('subscription_id') == identity:
                    entry.pop('subscription_id')
            self.file.write(value)

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

    def export_profiles(self):
        with self.lock:
            return {'format': 'yukiwire-profiles', 'version': 1,
                    'profiles': [{'name': p['name'], 'text': p['text']} for p in self._read()['profiles']]}

    def import_profiles(self, backup, validate):
        if (not isinstance(backup, dict) or backup.get('format') != 'yukiwire-profiles' or
                backup.get('version') != 1 or not isinstance(backup.get('profiles'), list) or
                not 1 <= len(backup['profiles']) <= 100):
            raise ValueError('Некорректный файл переноса профилей (допускается 1–100 профилей).')
        entries = []
        for item in backup['profiles']:
            if not isinstance(item, dict) or not isinstance(item.get('name'), str) or not isinstance(item.get('text'), str):
                raise ValueError('Некорректная запись профиля.')
            protocol = validate(item['text'])
            entries.append({'id': str(uuid.uuid4()), 'name': item['name'].strip()[:80] or 'Профиль',
                            'protocol': protocol, 'text': item['text']})
        with self.lock:
            value = self._read()
            existing = {p['text'] for p in value['profiles']}
            count = 0
            for entry in entries:
                if entry['text'] in existing:
                    continue
                value['profiles'].append(entry)
                existing.add(entry['text'])
                count += 1
            if not value['selected'] and value['profiles']:
                value['selected'] = value['profiles'][0]['id']
            self.file.write(value)  # One atomic write after the whole import was validated.
            return count
