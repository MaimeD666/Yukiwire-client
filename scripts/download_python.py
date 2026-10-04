"""Download an isolated Python runtime; leaves the user's Python installation alone."""
import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile

VERSION = '3.14.8'
# Published on the official Python release page.
SHA256 = 'a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310'
ROOT = Path(__file__).resolve().parents[1]


def install():
    folder = ROOT / 'runtime' / 'embedded-python'
    marker = folder / 'verified.json'
    if marker.is_file():
        hashes = json.loads(marker.read_text())
        if hashes.get('archive') == SHA256 and all((folder / name).is_file() and hashlib.sha256((folder / name).read_bytes()).hexdigest() == digest for name, digest in hashes['files'].items()):
            return folder
    url = f'https://www.python.org/ftp/python/{VERSION}/python-{VERSION}-embed-amd64.zip'
    with urllib.request.urlopen(url, timeout=90) as response:
        data = response.read(32 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise RuntimeError('Python runtime SHA256 mismatch')
    folder.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        if any(Path(name).name != name or Path(name).suffix not in ('.exe', '.dll', '.pyd', '.zip', '.txt', '._pth', '.cat') for name in names):
            raise RuntimeError('Unexpected embedded runtime layout')
        hashes = {}
        for name in names:
            content = archive.read(name)
            (folder / name).write_bytes(content)
            hashes[name] = hashlib.sha256(content).hexdigest()
    marker.write_text(json.dumps({'archive': SHA256, 'files': hashes}))
    return folder


if __name__ == '__main__':
    print(install())
