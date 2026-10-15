"""Verify the exact release package set before and after upload."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from yukiwire.version import VERSION, PACKAGE_NAME


def verify(folder, uploaded=None):
    folder = Path(folder)
    packages = {PACKAGE_NAME + '.zip', PACKAGE_NAME + '-setup.exe'}
    expected_files = packages | {'SHA256SUMS.txt'}
    if {p.name for p in folder.iterdir()} != expected_files:
        raise ValueError('Unexpected release files')
    checksums = {}
    for line in (folder / 'SHA256SUMS.txt').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match or match[2] not in packages or match[2] in checksums:
            raise ValueError('Invalid checksum manifest')
        checksums[match[2]] = match[1]
    if set(checksums) != packages:
        raise ValueError('Incomplete checksum manifest')
    for name, digest in checksums.items():
        if hashlib.sha256((folder / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Package checksum mismatch')
    with zipfile.ZipFile(folder / (PACKAGE_NAME + '.zip')) as archive:
        metadata = json.loads(archive.read('Yukiwire/portable.json'))
        if metadata.get('version') != VERSION or not metadata.get('tun_available'):
            raise ValueError('Wrong portable package')
    if uploaded:
        release = json.loads(Path(uploaded).read_text())
        if not release['draft'] or release['tag_name'] != 'v' + VERSION:
            raise ValueError('Wrong draft release')
        if {a['name'] for a in release['assets']} != expected_files:
            raise ValueError('Incomplete release upload')
        for asset in release['assets']:
            file = folder / asset['name']
            if asset['state'] != 'uploaded' or asset['size'] != file.stat().st_size or asset.get('digest') != 'sha256:' + hashlib.sha256(file.read_bytes()).hexdigest():
                raise ValueError('Upload integrity mismatch')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('folder', type=Path)
    parser.add_argument('--uploaded', type=Path)
    args = parser.parse_args()
    verify(args.folder, args.uploaded)
    print('Release artifacts verified.')
