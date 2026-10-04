"""Versioned data snapshots; verify Git blob identity, validate before atomic activation."""
import hashlib
import http.client
import json
from pathlib import Path
import re
import ssl
import time
from urllib.parse import urlsplit

from .paths import RUNTIME, CORE
from .storage import atomic_write

REPO = 'runetfreedom/russia-v2ray-rules-dat'


def varint(data, index):
    value, shift = 0, 0
    while index < len(data) and shift < 70:
        byte = data[index]
        index += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, index
        shift += 7
    raise ValueError('Повреждённый protobuf в списках маршрутизации.')


def fields(data):
    for field, wire, content in wire_fields(data):
        if wire == 2:
            yield field, content


def wire_fields(data):
    index = 0
    while index < len(data):
        tag, index = varint(data, index)
        wire = tag & 7
        if wire == 2:
            length, index = varint(data, index)
            end = index + length
            if end > len(data):
                raise ValueError('Обрыв файла geodata.')
            yield tag >> 3, wire, data[index:end]
            index = end
        elif wire == 0:
            content, index = varint(data, index)
            yield tag >> 3, wire, content
        elif wire in (1, 5):
            index += 8 if wire == 1 else 4
            if index > len(data):
                raise ValueError('Обрыв файла geodata.')
        else:
            raise ValueError('Некорректная структура geodata.')


def read_tags(path):
    data = memoryview(Path(path).read_bytes())
    tags = set()
    for field, record in fields(data):
        if field == 1:
            for child, content in fields(record):
                if child == 1:
                    tags.add(bytes(content).decode('ascii').lower())
                    break
    return tags


class RuleSets:
    def __init__(self, directory=RUNTIME / 'rulesets'):
        self.directory = Path(directory)
        self.active = self.directory / 'active.json'

    def metadata(self):
        if not self.active.exists():
            return {'version': 'Встроенные списки Xray', 'source': 'XTLS/Xray-core', 'updated': None, 'custom': False}
        manifest = json.loads(self.active.read_text(encoding='utf-8'))
        if manifest.get('custom') and not re.fullmatch(r'[0-9a-f]{40}', manifest.get('commit', '')):
            raise ValueError('Некорректная версия списков.')
        return manifest

    def tags(self):
        manifest = self.metadata()
        self.verify(manifest)
        if not manifest.get('custom'):
            folder, prefix = CORE.parent, ''
        else:
            folder = self.directory / manifest['commit']
            prefix = 'ext:../rulesets/' + manifest['commit'] + '/'
        result = {}
        site = folder / 'geosite.dat'
        ip = folder / 'geoip.dat'
        if site.exists():
            available = read_tags(site)
            for name in ('category-ru', 'ru-blocked', 'ru-available-only-inside'):
                if name in available:
                    result[name] = prefix + 'geosite.dat:' + name if prefix else 'geosite:' + name
        if ip.exists() and 'ru' in read_tags(ip):
            result['geoip-ru'] = prefix + 'geoip.dat:ru' if prefix else 'geoip:ru'
        return result

    def verify(self, manifest):
        if not manifest.get('custom'):
            return
        hashes = manifest.get('sha256', {})
        if set(hashes) != {'geoip.dat', 'geosite.dat'}:
            raise ValueError('В версии списков отсутствуют контрольные суммы.')
        folder = self.directory / manifest['commit']
        for name, digest in hashes.items():
            if not (folder / name).is_file() or hashlib.sha256((folder / name).read_bytes()).hexdigest() != digest:
                raise ValueError('Активные списки повреждены. Выполните откат или повторное обновление.')

    def membership(self, host, address):
        manifest = self.metadata()
        self.verify(manifest)
        folder = self.directory / manifest['commit'] if manifest.get('custom') else CORE.parent
        result = {'blocked': False, 'domestic': False, 'ru_ip': False}
        if host and (folder / 'geosite.dat').exists():
            for name, key in [('ru-blocked', 'blocked'), ('category-ru', 'domestic'), ('ru-available-only-inside', 'domestic')]:
                if match_site(folder / 'geosite.dat', name, host):
                    result[key] = True
        if address and (folder / 'geoip.dat').exists():
            result['ru_ip'] = match_ip(folder / 'geoip.dat', 'ru', address)
        return result

    def update(self, validate, proxy_port=None):
        reference = json.loads(download('https://api.github.com/repos/' + REPO + '/git/ref/heads/release', proxy_port, 2 * 1024 * 1024))
        commit = reference['object']['sha']
        if not re.fullmatch(r'[0-9a-f]{40}', commit):
            raise ValueError('GitHub вернул неверную версию списков.')
        commit_object = json.loads(download('https://api.github.com/repos/' + REPO + '/git/commits/' + commit, proxy_port, 2 * 1024 * 1024))
        tree = json.loads(download('https://api.github.com/repos/' + REPO + '/git/trees/' + commit_object['tree']['sha'], proxy_port, 4 * 1024 * 1024))
        blobs = {entry['path']: entry['sha'] for entry in tree['tree'] if entry['type'] == 'blob'}
        folder = self.directory / commit
        hashes = {}
        for name in ('geosite.dat', 'geoip.dat'):
            if name not in blobs:
                raise ValueError('В версии отсутствуют geo-файлы.')
            data = download('https://raw.githubusercontent.com/' + REPO + '/' + commit + '/' + name, proxy_port, 128 * 1024 * 1024)
            blob = hashlib.sha1(('blob %s\0' % len(data)).encode() + data).hexdigest()
            if blob != blobs[name]:
                raise ValueError('Содержимое списка не совпало с Git blob. Обновление отменено.')
            atomic_write(folder / name, data)
            read_tags(folder / name)
            hashes[name] = hashlib.sha256(data).hexdigest()
        if 'ru-blocked' not in read_tags(folder / 'geosite.dat'):
            raise ValueError('В списках нет категории ru-blocked. Обновление отменено.')
        prefix = 'ext:../rulesets/' + commit + '/'
        candidate_tags = {name: prefix + 'geosite.dat:' + name for name in ('category-ru', 'ru-blocked', 'ru-available-only-inside') if name in read_tags(folder / 'geosite.dat')}
        if 'ru' in read_tags(folder / 'geoip.dat'):
            candidate_tags['geoip-ru'] = prefix + 'geoip.dat:ru'
        validate(candidate_tags)
        previous = self.metadata()
        manifest = {'version': commit[:12], 'commit': commit, 'source': REPO, 'updated': int(time.time()), 'custom': True, 'sha256': hashes}
        if previous.get('commit') != commit:
            atomic_write(self.directory / 'previous.json', json.dumps(previous).encode())
        atomic_write(self.active, json.dumps(manifest).encode())
        return manifest

    def rollback(self, validate):
        path = self.directory / 'previous.json'
        if not path.exists():
            raise ValueError('Предыдущей версии списков пока нет.')
        previous = json.loads(path.read_text())
        if not previous.get('custom'):
            tags = {}
            if (CORE.parent / 'geosite.dat').exists() and 'category-ru' in read_tags(CORE.parent / 'geosite.dat'):
                tags['category-ru'] = 'geosite:category-ru'
            if (CORE.parent / 'geoip.dat').exists() and 'ru' in read_tags(CORE.parent / 'geoip.dat'):
                tags['geoip-ru'] = 'geoip:ru'
            validate(tags)
            current = self.metadata()
            atomic_write(self.active, json.dumps(previous).encode())
            atomic_write(path, json.dumps(current).encode())
            return previous
        commit = previous.get('commit', '')
        if not re.fullmatch(r'[0-9a-f]{40}', commit):
            raise ValueError('Некорректная предыдущая версия.')
        folder = self.directory / commit
        for name, digest in previous['sha256'].items():
            if name not in ('geoip.dat', 'geosite.dat') or hashlib.sha256((folder / name).read_bytes()).hexdigest() != digest:
                raise ValueError('Предыдущая версия повреждена.')
        prefix = 'ext:../rulesets/' + commit + '/'
        tags = {name: prefix + 'geosite.dat:' + name for name in ('category-ru', 'ru-blocked', 'ru-available-only-inside') if name in read_tags(folder / 'geosite.dat')}
        if 'ru' in read_tags(folder / 'geoip.dat'):
            tags['geoip-ru'] = prefix + 'geoip.dat:ru'
        validate(tags)
        current = self.metadata()
        atomic_write(self.active, json.dumps(previous).encode())
        atomic_write(path, json.dumps(current).encode())
        return previous


def category(path, name):
    data = memoryview(Path(path).read_bytes())
    for field, record in fields(data):
        if field != 1:
            continue
        code = None
        for child, content in fields(record):
            if child == 1:
                code = bytes(content).decode('ascii').lower()
                break
        if code == name:
            return record
    return None


def match_site(path, name, host):
    record = category(path, name)
    if record is None:
        return False
    host = host.lower()
    for field, domain in fields(record):
        if field != 2:
            continue
        kind, value = 0, ''
        for child, wire, content in wire_fields(domain):
            if child == 1 and wire == 0:
                kind = content
            elif child == 2 and wire == 2:
                value = bytes(content).decode('utf-8')
        normalized = value.lower()
        if kind == 0 and normalized in host or kind == 2 and (host == normalized or host.endswith('.' + normalized)) or kind == 3 and host == normalized:
            return True
        if kind == 1:
            try:
                if re.search(value, host):
                    return True
            except re.error:
                pass  # UI is a preview; Xray's RE2 remains authoritative.
    return False


def match_ip(path, name, address):
    record = category(path, name)
    if record is None:
        return False
    bits = address.max_prefixlen
    candidate = int(address)
    for field, cidr in fields(record):
        if field != 2:
            continue
        packed, prefix = b'', 0
        for child, wire, content in wire_fields(cidr):
            if child == 1 and wire == 2:
                packed = bytes(content)
            elif child == 2 and wire == 0:
                prefix = content
        if len(packed) * 8 == bits and 0 <= prefix <= bits:
            shift = bits - prefix
            if candidate >> shift == int.from_bytes(packed, 'big') >> shift:
                return True
    return False


def download(url, proxy_port, limit):
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname not in ('api.github.com', 'raw.githubusercontent.com'):
        raise ValueError('Недопустимый источник списков.')
    host = '127.0.0.1' if proxy_port else parsed.hostname
    port = proxy_port if proxy_port else 443
    connection = http.client.HTTPSConnection(host, port, timeout=30, context=ssl.create_default_context())
    if proxy_port:
        connection.set_tunnel(parsed.hostname, 443)
    try:
        connection.request('GET', parsed.path, headers={'Host': parsed.hostname, 'User-Agent': 'Yukiwire', 'Accept': 'application/vnd.github+json' if parsed.hostname == 'api.github.com' else '*/*'})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError('Источник списков ответил HTTP %s. Работающая версия сохранена.' % response.status)
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError('Список превышает допустимый размер.')
        return data
    finally:
        connection.close()
