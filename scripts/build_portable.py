"""Portable build with pinned embedded CPython; never copy user runtime state."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import ssl
import sys
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from build_native import build
from download_python import install as install_python

EXCLUDED_LIBRARY = {'site-packages', '__pycache__', 'test', 'tests', 'tkinter', 'idlelib',
                    'ensurepip', 'venv', 'turtledemo'}


def library_files(prefix):
    for path in sorted((prefix / 'Lib').rglob('*.py')):
        relative = path.relative_to(prefix / 'Lib')
        if not EXCLUDED_LIBRARY.intersection(relative.parts) and path.name != 'turtle.py':
            yield relative.as_posix(), path


def python_assets(prefix, generated):
    version = f'{sys.version_info.major}{sys.version_info.minor}'
    allowed = {}
    for name in ('python.exe', 'python3.dll', 'python' + version + '.dll',
                 'vcruntime140.dll', 'vcruntime140_1.dll'):
        source = prefix / name
        if source.is_file():
            allowed['python/' + name] = source
        elif name in ('python.exe', 'python' + version + '.dll'):
            raise RuntimeError('Missing interpreter component: ' + name)
    # DLLs is the installed standard library directory, never site-packages.
    for source in sorted((prefix / 'DLLs').iterdir()):
        if source.suffix.lower() in ('.dll', '.pyd') and not source.name.startswith(('_test', '_ctypes_test', '_tkinter', 'tcl', 'tk')):
            allowed['python/DLLs/' + source.name] = source
    library = generated / ('python' + version + '.zip')
    with zipfile.ZipFile(library, 'w', zipfile.ZIP_DEFLATED) as archive:
        for relative, source in library_files(prefix):
            archive.write(source, relative)
    allowed['python/' + library.name] = library
    paths = generated / ('python' + version + '._pth')
    # _pth ignores registry/PYTHONPATH and site; imports use bundled files only.
    paths.write_text(library.name + '\nDLLs\n.\n..\n', encoding='ascii')
    allowed['python/' + paths.name] = paths
    allowed['licenses/Python-LICENSE.txt'] = prefix / 'LICENSE.txt'
    return allowed


def embedded_assets(folder, generated):
    allowed = {}
    for source in sorted(folder.iterdir()):
        if source.suffix in ('.exe', '.dll', '.pyd', '.zip', '.cat') and source.name != 'pythonw.exe':
            allowed['python/' + source.name] = source
    library = next(folder.glob('python3*.zip'))
    filtered = generated / library.name
    with zipfile.ZipFile(library) as original, zipfile.ZipFile(filtered, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name in original.namelist():
            if not EXCLUDED_LIBRARY.intersection(Path(name).parts) and name not in ('turtle.pyc', 'turtle.py'):
                archive.writestr(name, original.read(name))
    allowed['python/' + library.name] = filtered
    paths = generated / (library.stem + '._pth')
    paths.write_text(library.name + '\n.\n..\n', encoding='ascii')
    allowed['python/' + paths.name] = paths
    allowed['licenses/Python-LICENSE.txt'] = folder / 'LICENSE.txt'
    result = subprocess.run([str(folder / 'python.exe'), '-c', 'import json,sys,ssl; print(json.dumps(dict(python=sys.version.split()[0],openssl=ssl.OPENSSL_VERSION)))'],
                            capture_output=True, text=True, check=True, timeout=10,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    return allowed, json.loads(result.stdout)


def write_archive(path, allowed, metadata):
    hashes = {}
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        for relative, source in sorted(allowed.items()):
            if Path(relative).is_absolute() or '..' in Path(relative).parts:
                raise ValueError('Unsafe distribution path')
            data = source.read_bytes()
            hashes[relative] = hashlib.sha256(data).hexdigest()
            archive.writestr('Yukiwire/' + relative, data)
        data = json.dumps(metadata, indent=2).encode()
        hashes['portable.json'] = hashlib.sha256(data).hexdigest()
        archive.writestr('Yukiwire/portable.json', data)
        archive.writestr('Yukiwire/SHA256SUMS.json', json.dumps(hashes, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--without-tun', action='store_true', help='Build local/system proxy preview without Wintun')
    parser.add_argument('--installed-python', action='store_true', help='Developer fallback: bundle the build interpreter')
    args = parser.parse_args()
    if os.name != 'nt' or struct.calcsize('P') != 8 or sys.version_info < (3, 11):
        raise RuntimeError('Use Windows x64 CPython 3.11+ from python.org')
    core = ROOT / 'runtime' / 'core'
    names = ['xray.exe', 'geoip.dat', 'geosite.dat', 'Xray-LICENSE.txt']
    if not args.without_tun:
        names += ['wintun.dll', 'Wintun-LICENSE.txt']
    for name in names:
        if not (core / name).is_file():
            raise RuntimeError('Missing core asset: ' + name + '; run the matching download script')
    shell = build()
    (ROOT / 'build').mkdir(exist_ok=True)
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    suffix = '-local' if args.without_tun else ''
    archive_path = dist / ('Yukiwire-0.4-preview-win-x64' + suffix + '.zip')
    with tempfile.TemporaryDirectory(prefix='portable-', dir=ROOT / 'build') as temporary:
        generated = Path(temporary)
        allowed = {'Yukiwire.exe': shell, 'README.md': ROOT / 'README.md',
                   'THIRD_PARTY.md': ROOT / 'THIRD_PARTY.md',
                   'licenses/OpenSSL-LICENSE.txt': ROOT / 'third_party' / 'licenses' / 'OpenSSL-LICENSE.txt'}
        for name in ('Loyalsoldier-LICENSE.txt', 'Geoip-LICENSE.txt', 'Geosite-LICENSE.txt'):
            allowed['licenses/' + name] = ROOT / 'third_party' / 'licenses' / name
        if args.installed_python:
            allowed.update(python_assets(Path(sys.base_prefix), generated))
            interpreter = {'python': sys.version.split()[0], 'openssl': ssl.OPENSSL_VERSION}
        else:
            assets, interpreter = embedded_assets(install_python(), generated)
            allowed.update(assets)
        for name in ('Microsoft.Web.WebView2.Core.dll', 'Microsoft.Web.WebView2.Wpf.dll', 'WebView2Loader.dll'):
            allowed[name] = shell.parent / name
        allowed['licenses/WebView2-LICENSE.txt'] = ROOT / 'runtime' / 'webview' / 'LICENSE.txt'
        for name in ('index.html', 'styles.css', 'app.js'):
            allowed['ui/' + name] = ROOT / 'ui' / name
        for name in ('yukiwire.ico', 'icon.svg'):
            allowed['ui/assets/' + name] = ROOT / 'ui' / 'assets' / name
        for source in sorted((ROOT / 'yukiwire').glob('*.py')):
            allowed['yukiwire/' + source.name] = source
        for name in ('worker.py', 'acceptance.py'):
            if (ROOT / 'scripts' / name).is_file():
                allowed['scripts/' + name] = ROOT / 'scripts' / name
        for name in ('recover-tun.ps1', 'inspect-tun.ps1', 'startup-recovery.ps1'):
            allowed['helpers/' + name] = ROOT / 'scripts' / name
        for name in names:
            allowed['core/' + name] = core / name
        for name in ('technical-test.cmd',):
            if (ROOT / name).is_file():
                allowed[name] = ROOT / name
        write_archive(archive_path, allowed, {'version': '0.4', **interpreter,
                                            'core': 'v26.9.30', 'tun_available': not args.without_tun})
    # Extract into a new directory: rebuilding never overwrites someone's saved state.
    destination = Path(tempfile.mkdtemp(prefix='Yukiwire-0.4-', dir=dist))
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(destination)
    print('Archive: ' + str(archive_path))
    print('Launch: ' + str(destination / 'Yukiwire' / 'Yukiwire.exe'))


if __name__ == '__main__':
    main()
