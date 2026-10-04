"""A separate Chromium profile explicitly uses our proxy, never global settings."""
import os
import json
from pathlib import Path
import subprocess
from .paths import RUNTIME


def browser_path():
    roots = [Path(os.environ.get(key, '')) for key in ('PROGRAMFILES', 'PROGRAMFILES(X86)', 'LOCALAPPDATA') if os.environ.get(key)]
    for relative in ('Google/Chrome/Application/chrome.exe', 'Microsoft/Edge/Application/msedge.exe'):
        for root in roots:
            candidate = root / relative
            if candidate.is_file():
                return candidate
    raise ValueError('Не найден Chrome или Edge. Укажите HTTP-прокси 127.0.0.1:11809 в браузере с отдельным профилем.')


def command(executable, directory):
    return [str(executable), '--user-data-dir=' + str(directory), '--proxy-server=http://127.0.0.1:11809',
            '--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
            '--no-first-run', '--no-default-browser-check', '--new-window', 'https://chatgpt.com/']


def open_browser():
    executable = browser_path()
    directory = RUNTIME / 'browser' / executable.stem
    directory.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(command(executable, directory), stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        code = process.wait(timeout=.25)
        if code:
            raise ValueError('Браузер завершился при запуске (код %s). Настройки Windows не изменены.' % code)
    except subprocess.TimeoutExpired:
        pass
    return executable.stem


def main():
    try:
        result = {'event': 'browser_opened', 'browser': open_browser()}
    except Exception as exc:
        result = {'event': 'error', 'operation': 'open_browser',
                  'message': str(exc) if isinstance(exc, ValueError) else 'Не удалось открыть браузер с прокси Yukiwire.'}
    print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
