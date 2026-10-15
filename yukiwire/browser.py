"""A separate Chromium profile explicitly uses our proxy, never global settings."""
import os
import json
from pathlib import Path
import subprocess
import argparse
from .paths import RUNTIME, STATE
from .routing import browser_home
from .storage import SecureFile
from .network import process_identity


def browser_path():
    roots = [Path(os.environ.get(key, '')) for key in ('PROGRAMFILES', 'PROGRAMFILES(X86)', 'LOCALAPPDATA') if os.environ.get(key)]
    for relative in ('Google/Chrome/Application/chrome.exe', 'Microsoft/Edge/Application/msedge.exe'):
        for root in roots:
            candidate = root / relative
            if candidate.is_file():
                return candidate
    raise ValueError('Не найден Chrome или Edge. Адрес локального прокси доступен в настройках подключения.')


def command(executable, directory, proxy_port=0, homepage='about:blank'):
    if type(proxy_port) is not int or not 0 <= proxy_port <= 65535:
        raise ValueError('Некорректный порт браузерного прокси.')
    return [str(executable), '--user-data-dir=' + str(directory),
            '--proxy-server=http://127.0.0.1:%d' % proxy_port if proxy_port else '--no-proxy-server',
            '--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
            '--no-first-run', '--no-default-browser-check', '--new-window', browser_home(homepage)]


def open_browser(proxy_port=0):
    executable = browser_path()
    directory = RUNTIME / 'browser' / executable.stem
    directory.mkdir(parents=True, exist_ok=True)
    record = SecureFile(STATE / ('browser-' + executable.stem + '.dpapi'))
    previous = record.read({})
    # Chromium ignores a new --proxy-server when reusing its running profile.
    # Keep cookies/profile stable, but never silently reuse a dead endpoint.
    if (previous and previous.get('port') != proxy_port and
            process_identity(previous['pid']) == previous.get('started')):
        raise ValueError('Закройте окно браузера Yukiwire и откройте его снова: после переподключения изменился адрес прокси.')
    settings = SecureFile(STATE / 'settings.dpapi').read({})
    process = subprocess.Popen(command(executable, directory, proxy_port, settings.get('browser_home', 'about:blank')), stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        code = process.wait(timeout=.25)
        if code:
            raise ValueError('Браузер завершился при запуске (код %s). Настройки Windows не изменены.' % code)
    except subprocess.TimeoutExpired:
        identity = process_identity(process.pid)
        if identity is not None:
            record.write({'pid': process.pid, 'started': identity, 'port': proxy_port})
    return executable.stem


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--proxy-port', type=int, default=0)
    args = parser.parse_args()
    try:
        result = {'event': 'browser_opened', 'browser': open_browser(args.proxy_port)}
    except Exception as exc:
        result = {'event': 'error', 'operation': 'open_browser',
                  'message': str(exc) if isinstance(exc, ValueError) else 'Не удалось открыть браузер с прокси Yukiwire.'}
    print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
