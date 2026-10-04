"""Install/upgrade/uninstall a test-identity Setup under build; never connect a VPN."""
import argparse
import ctypes
from ctypes import wintypes
from pathlib import Path
import subprocess
import tempfile
import time
import winreg

from build_installer import ARCHIVE, ROOT, build, payload

KEY = r'Software\Microsoft\Windows\CurrentVersion\Uninstall\Yukiwire.Desktop.InstallerTest_is1'


def registration():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            return winreg.QueryValueEx(key, 'InstallLocation')[0]
    except FileNotFoundError:
        return None


def run(command, success=True):
    result = subprocess.run(list(map(str, command)), timeout=90, creationflags=subprocess.CREATE_NO_WINDOW)
    if success and result.returncode != 0 or not success and result.returncode == 0:
        for argument in command:
            if str(argument).startswith('/LOG='):
                log = Path(str(argument)[5:])
                if log.is_file():
                    print('\n'.join(log.read_text(encoding='utf-8-sig', errors='replace').splitlines()[-35:]))
        raise RuntimeError('Unexpected installer exit code: ' + str(result.returncode))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('archive', nargs='?', type=Path, default=ARCHIVE)
    args = parser.parse_args()
    if registration() is not None:
        raise RuntimeError('An earlier installer test is registered; refusing to overwrite it')
    setup = build(args.archive, test=True)
    files, _ = payload(args.archive)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateMutexW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    # The test requires the existing shared WebView2 Runtime; it never installs prerequisites.
    webview_key = r'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    detected = False
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, webview_key, 0, winreg.KEY_READ | winreg.KEY_WOW64_32KEY) as key:
                detected |= winreg.QueryValueEx(key, 'pv')[0] not in ('', '0.0.0.0')
        except FileNotFoundError:
            pass
    if not detected:
        raise RuntimeError('Install WebView2 separately before running this isolated installer test')
    # This directory is created by us inside the workspace. User installations are never targets.
    with tempfile.TemporaryDirectory(prefix='setup-check-', dir=ROOT / 'build') as temporary:
        target = Path(temporary) / 'Yukiwire test with spaces'
        command = [setup, '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/NOICONS',
                   '/TASKS=', '/DIR=' + str(target), '/LOG=' + str(Path(temporary) / 'setup.log')]
        uninstaller = target / 'unins000.exe'
        try:
            run(command)
            if not registration() or Path(registration()).resolve() != target.resolve():
                raise RuntimeError('Wrong per-user installer registration')
            for name, data in files.items():
                if (target / name).read_bytes() != data:
                    raise RuntimeError('Installed payload mismatch: ' + name)
            private = target / 'state/profiles.dpapi'
            private.parent.mkdir(exist_ok=True)
            private.write_bytes(b'installer-test-private-sentinel')
            (target / 'ui/app.js').write_bytes(b'old-public-file')
            run(command)
            assert (target / 'ui/app.js').read_bytes() == files['ui/app.js']
            assert private.read_bytes() == b'installer-test-private-sentinel'
            print('Install/upgrade passed: exact payload, per-user registration, private data preserved.')
            journal = target / 'state/network-lease.dpapi'
            journal.write_bytes(b'installer-test-pending-recovery')
            run(command, success=False)
            run([uninstaller, '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART'], success=False)
            assert journal.exists() and (target / 'Yukiwire.exe').exists()
            journal.unlink()
            mutex = kernel.CreateMutexW(None, False, 'Local\\Yukiwire.NativeShell')
            if not mutex:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                run(command, success=False)
                run([uninstaller, '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART'], success=False)
            finally:
                kernel.CloseHandle(mutex)
            print('Recovery journal and live application mutex both block update/uninstall.')
            run([uninstaller, '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART'])
            for _ in range(40):
                if not (target / 'Yukiwire.exe').exists() and registration() is None:
                    break
                time.sleep(.1)
            assert not (target / 'Yukiwire.exe').exists() and registration() is None
            assert private.read_bytes() == b'installer-test-private-sentinel'
            print('Uninstall passed: public files/registration removed, private data preserved.')
        finally:
            # Cleanup only the test registration and its own files after a failed assertion.
            journal = target / 'state/network-lease.dpapi'
            journal.unlink(missing_ok=True)
            if uninstaller.is_file() and registration() and Path(registration()).resolve() == target.resolve():
                run([uninstaller, '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART'])


if __name__ == '__main__':
    main()
