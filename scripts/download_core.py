"""Download a pinned official Xray release and verify its published digest."""
import hashlib
import io
from pathlib import Path
import urllib.request
import zipfile
import re

VERSION = 'v26.9.30'
ROOT = Path(__file__).resolve().parents[1]


def main():
    base = f'https://github.com/XTLS/Xray-core/releases/download/{VERSION}/Xray-windows-64.zip'
    def fetch(url):
        request = urllib.request.Request(url, headers={'User-Agent': 'Yukiwire-preview'})
        with urllib.request.urlopen(request, timeout=90) as response:
            return response.read()
    archive = fetch(base)
    digest = fetch(base + '.dgst').decode()
    expected = hashlib.sha256(archive).hexdigest()
    if expected.lower() not in [s.lower() for s in re.findall(r'\b[0-9a-fA-F]{64}\b', digest)]:
        raise RuntimeError('SHA256 mismatch; installation aborted')
    target = ROOT / 'runtime' / 'core'
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        if 'xray.exe' not in bundle.namelist():
            raise RuntimeError('Archive has no xray.exe')
        for name in ('geoip.dat', 'geosite.dat'):
            if name not in bundle.namelist():
                continue
            (target / name).write_bytes(bundle.read(name))
        (target / 'xray.exe').write_bytes(bundle.read('xray.exe'))
    request = urllib.request.Request('https://raw.githubusercontent.com/XTLS/Xray-core/' + VERSION + '/LICENSE', headers={'User-Agent': 'Yukiwire'})
    with urllib.request.urlopen(request, timeout=30) as response:
        (target / 'Xray-LICENSE.txt').write_bytes(response.read())
    print(f'Installed Xray {VERSION}; SHA256 {expected}')


if __name__ == '__main__':
    main()
