"""Verify the actual ZIP in an isolated path with spaces and Cyrillic characters."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]


class VerifiedDirectory(tempfile.TemporaryDirectory):
    def cleanup(self):
        target = Path(self.name).resolve()
        workspace = (ROOT / 'build').resolve()
        if target == workspace or not target.is_relative_to(workspace):
            raise RuntimeError('Refusing cleanup outside the owned build directory')
        deadline = time.monotonic() + 15
        while True:
            try:
                super().cleanup()
                return
            except PermissionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.25)  # WebView2 finishes releasing its own cache after disposal.


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('archive', type=Path)
    parser.add_argument('--native', action='store_true', help='Also exercise WebView2 and helper with bundled backend')
    args = parser.parse_args()
    (ROOT / 'build').mkdir(exist_ok=True)
    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'portable-real-core-fixture' * 256
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *values):
            pass
    server = HTTPServer(('127.0.0.1', 0), Origin)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with VerifiedDirectory(prefix='portable тест ', dir=ROOT / 'build') as temporary:
            directory = Path(temporary)
            assert directory.resolve().is_relative_to((ROOT / 'build').resolve())
            with zipfile.ZipFile(args.archive) as archive:
                names = archive.namelist()
                forbidden = {'state', 'browser', 'profiles', 'sessions', 'site-packages', 'tests', '__pycache__'}
                assert not any(forbidden.intersection(Path(name).parts) for name in names), 'Private/runtime paths in archive'
                assert not any('tkinter' in name.lower() or 'tcl86' in name.lower() or 'tk86' in name.lower() for name in names)
                manifest = json.loads(archive.read('Yukiwire/SHA256SUMS.json'))
                assert set(names) == {'Yukiwire/' + name for name in manifest} | {'Yukiwire/SHA256SUMS.json'}
                for name, expected in manifest.items():
                    assert hashlib.sha256(archive.read('Yukiwire/' + name)).hexdigest() == expected
                library = next(name for name in names if name.startswith('Yukiwire/python/python') and name.endswith('.zip'))
                import io
                with zipfile.ZipFile(io.BytesIO(archive.read(library))) as stdlib:
                    assert not any({'site-packages', 'test', 'tests', 'tkinter', 'idlelib'}.intersection(Path(name).parts) for name in stdlib.namelist())
                archive.extractall(directory)
            bundle = directory / 'Yukiwire'
            python = bundle / 'python' / 'python.exe'
            environment = dict(os.environ, PYTHONHOME=str(directory / 'missing Python'),
                               PYTHONPATH=str(directory / 'untrusted site-packages'),
                               YUKIWIRE_ROOT=str(directory / 'wrong root'), YUKIWIRE_PYTHON='missing-python.exe',
                               PYTHONIOENCODING='utf-8')
            code = '''
import http.client, sys
from pathlib import Path
from yukiwire.backend import Session
from yukiwire.paths import ROOT, CORE, PORTABLE
from scripts.acceptance import Backend
assert sys.flags.isolated and PORTABLE and CORE.is_file()
assert all(Path(p).resolve().is_relative_to(ROOT) for p in sys.path)
profile = 'vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls'
session = Session()
try:
    session.start(profile)
    c = http.client.HTTPConnection('127.0.0.1', 11809, timeout=5)
    try:
        c.request('GET', 'http://127.0.0.1:' + sys.argv[1] + '/')
        assert c.getresponse().read().startswith(b'portable-real-core-fixture')
    finally:
        c.close()
    assert session.telemetry.sample()['download_bytes'] > 0
finally:
    session.stop()
backend = Backend()
try:
    backend.send(action='start', profile=profile)
    backend.wait('started', timeout=20)
    backend.send(action='stop')
    backend.wait('stopped', timeout=15)
finally:
    backend.close()
print('Bundled runtime, real-core traffic, metrics and backend start/stop: passed')
'''
            subprocess.run([str(python), '-B', '-c', code, str(server.server_port)], cwd=directory,
                           env=environment, check=True, timeout=45, creationflags=subprocess.CREATE_NO_WINDOW)
            print('Bundled runtime, real-core traffic, metrics and backend start/stop: passed')
            if args.native:
                profile = directory / 'public-fixture.txt'
                profile.write_text('vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls', encoding='utf-8')
                process = subprocess.Popen([str(bundle / 'Yukiwire.exe'), '--integration-worker', str(profile)],
                                           cwd=directory, env=environment, creationflags=subprocess.CREATE_NO_WINDOW)
                try:
                    process.wait(timeout=50)
                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=5)
                report = json.loads((bundle / 'native-integration-report.json').read_text())
                assert report['lifecycle_passed'], 'Native bundled backend integration failed'
                print('Packaged WebView2, secure helper and bundled backend start/stop: passed')
            print('Archive allowlist, checksums, isolated imports, spaces/Cyrillic path: passed')
    finally:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
