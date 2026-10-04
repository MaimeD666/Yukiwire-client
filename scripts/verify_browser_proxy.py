"""Real headless browser -> Yukiwire -> local fixture; no Windows network changes."""
import ctypes
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from yukiwire.backend import Session
from yukiwire.browser import browser_path, command
from yukiwire.paths import RUNTIME
from yukiwire.process import ExtendedLimits
from yukiwire.routing import DEFAULTS


def verify():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            data = b'<html><body>YUKIWIRE_BROWSER_PROXY_CONFIRMED</body></html>'
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *args):
            pass
    fixture = HTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=fixture.serve_forever, daemon=True).start()
    session = Session()
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    job = kernel.CreateJobObjectW(None, None)
    process = None
    RUNTIME.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.TemporaryDirectory(prefix='browser-verification-', dir=RUNTIME, ignore_cleanup_errors=True)
    try:
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000
        if not job or not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise RuntimeError('Cannot guard the test browser')
        session.start('vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls', dict(DEFAULTS, auto_reconnect=False))
        args = command(browser_path(), Path(temporary.name))[:-1] + [
            '--proxy-bypass-list=<-loopback>', '--headless=new', '--dump-dom', '--disable-gpu', '--enable-logging=stderr',
            '--disable-background-networking', 'http://127.0.0.1:%s/' % fixture.server_port]
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   creationflags=subprocess.CREATE_NO_WINDOW | 0x4)
        if not kernel.AssignProcessToJobObject(job, wintypes.HANDLE(int(process._handle))):
            raise RuntimeError('Cannot isolate the test browser')
        native = ctypes.WinDLL('ntdll')
        native.NtResumeProcess.argtypes = [wintypes.HANDLE]
        if native.NtResumeProcess(wintypes.HANDLE(int(process._handle))) != 0:
            raise RuntimeError('Cannot resume the test browser')
        output, errors = process.communicate(timeout=20)
        stats = session.telemetry.sample()
        return {'browser_rendered_fixture': b'YUKIWIRE_BROWSER_PROXY_CONFIRMED' in output,
                'traffic_passed_through_yukiwire': stats['download_bytes'] > 0,
                'local_fixture_routed_directly': stats['direct_bytes'] > 0,
                'browser_exit_code': process.returncode,
                'browser_output_bytes': len(output),
                'browser_error_codes': sorted(set(re.findall(r'ERR_[A-Z_]+', output.decode('utf-8', errors='replace')))),
                'startup_error_categories': sorted(set(re.findall(r'(?i)access is denied|permission denied|sandbox|fatal|check failed', errors.decode('utf-8', errors='replace'))))}
    finally:
        if job:
            kernel.CloseHandle(job)  # Kills only this test's browser descendants.
        if process:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()
        session.stop()
        fixture.shutdown()
        fixture.server_close()
        temporary.cleanup()


if __name__ == '__main__':
    try:
        result = verify()
    except Exception as exc:
        result = {'passed': False, 'error_type': type(exc).__name__}
    print(json.dumps(result))
    raise SystemExit(0 if all(result.get(key) is True for key in ('browser_rendered_fixture', 'traffic_passed_through_yukiwire', 'local_fixture_routed_directly')) else 1)
