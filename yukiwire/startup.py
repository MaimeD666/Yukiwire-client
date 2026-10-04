"""A temporary user logon task persists until owned network recovery succeeds."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import winreg
from .paths import ROOT, RUNTIME, PORTABLE
import sys


def specification(path, command, kind=None):
    suffix = hashlib.sha256(str(Path(path).resolve()).lower().encode()).hexdigest()[:20]
    return {'name': 'Yukiwire.Recovery-' + suffix, 'executable': command[0],
            'arguments': subprocess.list2cmdline(command[1:]), 'directory': str(ROOT),
            'level': 'Highest' if kind == 'tun' else 'Limited'}


def task(mode, spec):
    script = RUNTIME / 'helpers' / 'startup-recovery.ps1' if PORTABLE else ROOT / 'scripts' / 'startup-recovery.ps1'
    payload = base64.b64encode(json.dumps(spec).encode('utf-8')).decode('ascii')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                             '-File', str(script), '-Mode', mode, '-PayloadB64', payload],
                            capture_output=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise ValueError('Не удалось настроить задачу восстановления Windows. Сетевые изменения не будут применены.')


def register(path, command, kind):
    task('Register', specification(path, command, kind))


def unregister(path, command):
    task('Remove', specification(path, command))
    # Remove only the exact legacy command; never another installation's value.
    legacy = subprocess.list2cmdline(command)
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\RunOnce',
                            0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
            current, _ = winreg.QueryValueEx(key, 'Yukiwire.Recovery')
            if current == legacy:
                winreg.DeleteValue(key, 'Yukiwire.Recovery')
    except FileNotFoundError:
        pass
