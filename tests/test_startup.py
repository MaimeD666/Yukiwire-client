import base64
import json
from pathlib import Path
import subprocess
import unittest

from yukiwire.startup import specification

ROOT = Path(__file__).resolve().parents[1]


class StartupTests(unittest.TestCase):
    def test_paths_with_spaces_have_stable_owned_task_identity(self):
        path = ROOT / 'folder with spaces' / 'network-lease.dpapi'
        command = ['C:\\Python runtime\\python.exe', 'C:\\App folder\\worker.py', '--worker', 'yukiwire.recovery', '--journal', str(path)]
        proxy = specification(path, command, 'system')
        tun = specification(path, command, 'tun')
        self.assertRegex(proxy['name'], r'^Yukiwire\.Recovery-[0-9a-f]{20}$')
        self.assertEqual(proxy['name'], tun['name'])
        self.assertEqual(proxy['level'], 'Limited')
        self.assertEqual(tun['level'], 'Highest')
        self.assertEqual(proxy['arguments'], subprocess.list2cmdline(command[1:]))

    def test_different_installations_have_different_task_names(self):
        first = specification(ROOT / 'a' / 'journal.dpapi', ['python.exe'])
        second = specification(ROOT / 'b' / 'journal.dpapi', ['python.exe'])
        self.assertNotEqual(first['name'], second['name'])

    def test_all_recovery_helpers_parse_without_executing_them(self):
        files = [str(ROOT / 'scripts' / name) for name in ('startup-recovery.ps1', 'inspect-tun.ps1', 'recover-tun.ps1')]
        payload = base64.b64encode(json.dumps(files).encode()).decode()
        code = "$ErrorActionPreference='Stop'; $paths=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + payload + "')) | ConvertFrom-Json; foreach ($p in $paths) { $tokens=$null; $errors=$null; [Management.Automation.Language.Parser]::ParseFile($p,[ref]$tokens,[ref]$errors) | Out-Null; if ($errors.Count) { throw 'Invalid recovery script syntax' } }"
        encoded = base64.b64encode(code.encode('utf-16-le')).decode()
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                                capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode, 0, 'PowerShell parser rejected a recovery helper')
