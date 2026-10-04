"""Install the pinned official driver library; does not create an adapter."""
import hashlib
import io
from pathlib import Path
import urllib.request
import zipfile

VERSION = '0.14.1'
SHA256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
ROOT = Path(__file__).resolve().parents[1]


def main():
    request = urllib.request.Request('https://www.wintun.net/builds/wintun-' + VERSION + '.zip', headers={'User-Agent': 'Yukiwire'})
    with urllib.request.urlopen(request, timeout=90) as response:
        data = response.read(16 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise RuntimeError('Wintun SHA256 mismatch; installation aborted')
    folder = ROOT / 'runtime' / 'core'
    folder.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        (folder / 'wintun.dll').write_bytes(archive.read('wintun/bin/amd64/wintun.dll'))
        (folder / 'Wintun-LICENSE.txt').write_bytes(archive.read('wintun/LICENSE.txt'))
    print('Installed Wintun ' + VERSION + ' library; no network changes')


if __name__ == '__main__':
    main()
