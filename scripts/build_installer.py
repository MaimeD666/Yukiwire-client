"""Build Setup.exe from the exact, hash-verified portable payload."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import zipfile

from download_installer_tools import install

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / 'dist/Yukiwire-0.4-preview-win-x64.zip'


def payload(archive_path):
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        if len(names) > 2000 or sum(item.file_size for item in archive.infolist()) > 512 * 1024 * 1024:
            raise ValueError('Unreasonable installer payload size')
        if len(set(name.casefold() for name in names)) != len(names):
            raise ValueError('Duplicate installer payload paths')
        files = {}
        public_folders = {'python', 'yukiwire', 'core', 'ui', 'docs', 'helpers', 'scripts', 'licenses'}
        public_files = {'Yukiwire.exe', 'README.md', 'THIRD_PARTY.md', 'TESTING.md',
                        'technical-test.cmd', 'portable.json', 'SHA256SUMS.json',
                        'Microsoft.Web.WebView2.Core.dll', 'Microsoft.Web.WebView2.Wpf.dll', 'WebView2Loader.dll'}
        for name in names:
            if not name.startswith('Yukiwire/'):
                raise ValueError('Unexpected archive root')
            relative = name[len('Yukiwire/'):]
            parts = relative.split('/')
            if (any(part in ('', '.', '..') or part.endswith((' ', '.')) or Path(part).is_reserved() for part in parts) or
                    any(char in relative for char in ('\\', ':', '"', '\r', '\n', '{', '}', '<', '>', '|', '?', '*')) or
                    relative.lower().endswith(('.dpapi', '.log')) or
                    not (relative in public_files or len(parts) > 1 and parts[0] in public_folders)):
                raise ValueError('Unsafe or private installer payload path: ' + relative)
            files[relative] = archive.read(name)
    hashes = json.loads(files['SHA256SUMS.json'])
    if set(files) != set(hashes) | {'SHA256SUMS.json'}:
        raise ValueError('Installer payload differs from its manifest')
    for name, digest in hashes.items():
        if hashlib.sha256(files[name]).hexdigest() != digest:
            raise ValueError('Installer payload hash mismatch: ' + name)
    metadata = json.loads(files['portable.json'])
    if not re.fullmatch(r'\d+\.\d+(?:\.\d+)?', metadata['version']) or not metadata.get('tun_available'):
        raise ValueError('Expected a versioned Windows x64 payload with TUN')
    if not {'Yukiwire.exe', 'python/python.exe', 'ui/assets/yukiwire.ico', 'scripts/worker.py'}.issubset(files):
        raise ValueError('Incomplete application payload')
    return files, metadata


def build(archive_path=ARCHIVE, test=False):
    files, metadata = payload(archive_path)
    compiler, bootstrapper = install()
    version = metadata['version']
    name = f'Yukiwire-{version}-preview-win-x64-setup'
    output = ROOT / ('build/installer-tests' if test else 'dist')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='installer-payload-', dir=ROOT / 'build') as temporary:
        staged = Path(temporary)
        lines = []
        for relative, data in sorted(files.items()):
            target = staged / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            parent = str(PurePosixPath(relative).parent).replace('/', '\\')
            destination = '{app}' + ('\\' + parent if parent != '.' else '')
            source = str(target).replace('{', '{{').replace('"', '""')
            lines.append(f'Source: "{source}"; DestDir: "{destination}"; Flags: ignoreversion')
        include = staged / 'payload.iss'
        include.write_text('\n'.join(lines), encoding='utf-8-sig')
        version_info = '.'.join((version.split('.') + ['0'] * 4)[:4])
        command = [str(compiler), '/Qp', '/DPayloadInclude=' + str(include), '/DAppVersion=' + version + ' preview',
                   '/DVersionInfoVersion=' + version_info, '/DAppIcon=' + str(staged / 'ui/assets/yukiwire.ico'),
                   '/DBootstrapper=' + str(bootstrapper), '/DOutputDir=' + str(output), '/DOutputName=' + name]
        if test:
            command.append('/DInstallerTest')
        command.append(str(ROOT / 'packaging/windows/Yukiwire.iss'))
        result = subprocess.run(command, timeout=180, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:
            print((result.stdout + result.stderr).decode('utf-8', errors='replace'))
        result.check_returncode()
    setup = output / (name + '.exe')
    if not setup.is_file():
        raise RuntimeError('Installer compiler produced no output')
    if not test:
        checksums = ROOT / 'dist/SHA256SUMS.txt'
        checksums.write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n'
                                   for path in (Path(archive_path), setup)), encoding='ascii')
    return setup


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('archive', nargs='?', type=Path, default=ARCHIVE)
    parser.add_argument('--test-build', action='store_true', help='Use a separate uninstall registry identity for lifecycle tests')
    args = parser.parse_args()
    print(build(args.archive, args.test_build))


if __name__ == '__main__':
    main()
