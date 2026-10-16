"""Pinned, unmodified RU geodata snapshot for offline first launch."""
import hashlib
import json
from pathlib import Path
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from yukiwire.geodata import REPO, read_tags
from yukiwire.storage import atomic_write

COMMIT = '88549b306b2b19c6e19ddd09fe9f27f4fb92df10'
SOURCE_COMMIT = 'f175e3f94891dbc1bb88edfc2d9d85f5a9051a23'
HASHES = {
    'geoip.dat': '7298269d18341f7d0b92c9ae0737d885dc49258e110798cb639b74f02b79bb0c',
    'geosite.dat': '76fdbe01687a6cc7683b50c38ceea84941458e8371d215918daf555665a537cd',
}


def install(directory=ROOT / 'runtime' / 'bundled-rules'):
    directory = Path(directory)
    for name, digest in HASHES.items():
        target = directory / name
        if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == digest:
            continue
        urls = ('https://raw.githubusercontent.com/' + REPO + '/' + COMMIT + '/' + name,
                'https://cdn.jsdelivr.net/gh/' + REPO + '@' + COMMIT + '/' + name)
        data = None
        for url in urls:
            try:
                with urllib.request.urlopen(url, timeout=90) as response:
                    candidate = response.read(128 * 1024 * 1024 + 1)
                if hashlib.sha256(candidate).hexdigest() != digest:
                    raise ValueError('Bundled geodata SHA256 mismatch')
                data = candidate
                break
            except (OSError, ValueError):
                continue
        if data is None:
            raise RuntimeError('Cannot download pinned bundled rules: ' + name)
        atomic_write(target, data)
    if not {'category-ru', 'ru-blocked', 'ru-available-only-inside'} <= read_tags(directory / 'geosite.dat'):
        raise ValueError('Bundled geosite is missing required categories')
    if 'ru' not in read_tags(directory / 'geoip.dat'):
        raise ValueError('Bundled geoip is missing RU')
    manifest = {'version': 'Bundled ' + COMMIT[:12], 'commit': COMMIT, 'source': REPO,
                'updated': None, 'custom': False, 'sha256': HASHES}
    atomic_write(directory / 'rules.json', json.dumps(manifest, indent=2).encode())
    return directory


if __name__ == '__main__':
    print(install())
