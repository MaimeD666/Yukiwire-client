"""Real network changes, ONLY on a disposable GitHub-hosted Windows VM.

Uses a public synthetic VLESS peer. Never loads a saved user profile.
"""
import ctypes
from ctypes import wintypes
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def require_disposable_runner():
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or
            not ctypes.windll.shell32.IsUserAnAdmin()):
        raise RuntimeError('This network-changing test requires an elevated disposable GitHub-hosted Windows runner')


def wait_for(predicate, description, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.2)
    raise AssertionError(description)


def port_ready(port):
    with socket.socket() as connection:
        connection.settimeout(.2)
        return connection.connect_ex(('127.0.0.1', port)) == 0


def inbound_bytes(session, tag):
    endpoint = session.endpoints['metrics']
    connection = http.client.HTTPConnection('127.0.0.1', endpoint.port, timeout=3)
    try:
        connection.request('GET', 'http://metrics.internal/debug/vars', headers=endpoint.headers)
        response = connection.getresponse()
        assert response.status == 200
        stats = json.loads(response.read(1024 * 1024))['stats'].get('inbound', {}).get(tag, {})
        return int(stats.get('downlink', 0))
    finally:
        connection.close()


def terminate_owned(pid, started):
    from yukiwire.network import process_identity
    assert process_identity(pid) == started
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = api.OpenProcess(1, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        assert api.TerminateProcess(handle, 91)
    finally:
        api.CloseHandle(handle)


def direct_tcp():
    try:
        with socket.create_connection(('1.1.1.1', 443), timeout=3):
            return True
    except OSError:
        return False


def rescue(identity, executable):
    # This binary is never packaged or installed. Parent death/timeout restores
    # only the deterministic filter keys of this component and current account.
    framework = Path(os.environ['WINDIR']) / 'Microsoft.NET/Framework64/v4.0.30319'
    target = ROOT / 'build/network/NetworkRescue.exe'
    subprocess.run([str(framework / 'csc.exe'), '/nologo', '/target:winexe', '/platform:x64',
                    '/out:' + str(target), str(ROOT / 'native/NetworkFilter.cs'),
                    str(ROOT / 'tests/NetworkRescue.cs')], check=True)
    sid = subprocess.check_output(['whoami', '/user', '/fo', 'csv', '/nh'], encoding='utf-8').strip().split(',')[-1].strip('"')
    from yukiwire.network import process_identity
    return subprocess.Popen([str(target), str(os.getpid()), str(process_identity(os.getpid())),
                             identity + ':' + sid, str(executable)], creationflags=subprocess.CREATE_NO_WINDOW)


def verify():
    require_disposable_runner()
    from yukiwire.broker import installed_helper
    from yukiwire.health import probe_https
    from yukiwire.network import WinInetProxy, process_identity, tun_clean
    from yukiwire.paths import STATE
    from yukiwire.process import CoreProcess
    from yukiwire.routing import DEFAULTS
    from yukiwire.session import Session
    from yukiwire.windows_snapshot import adapters, routes, foreign_snapshot

    assert not any(STATE.glob('*.dpapi')), 'Runner must not contain user state'
    before_proxy, before_foreign = WinInetProxy().read(), foreign_snapshot()
    default = next(r for r in routes() if r['prefix'] == '0.0.0.0/0')
    physical = next(a['name'] for a in adapters() if a['index'] == default['index'])
    helper, identity = installed_helper()
    executable = helper.parent / 'xray.exe'
    rescue(identity, executable)
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    peer = CoreProcess(executable, {
        'log': {'loglevel': 'warning'},
        'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'vless',
                      'settings': {'decryption': 'none', 'clients': [{'id': '00000000-0000-4000-8000-000000000001'}]}}],
        'outbounds': [{'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIPv4'},
                       'streamSettings': {'sockopt': {'interface': physical}}}]})
    wait_for(lambda: port_ready(port), 'Synthetic peer did not listen')
    profile = 'vless://00000000-0000-4000-8000-000000000001@127.0.0.1:%d?security=none' % port
    try:
        for capture, combined, protection in [('system', False, False), ('tun', False, False),
                                               ('tun', True, False), ('system', False, True), ('tun', True, True)]:
            print('Real capture: %s, combined=%s, protection=%s' % (capture, combined, protection), flush=True)
            assert direct_tcp(), 'Baseline internet must be reachable before protection'
            session = Session()
            try:
                session.start(profile, dict(DEFAULTS, capture=capture, tun_system_proxy=combined,
                                            kill_switch=protection, preset='all', auto_reconnect=False))
                print('Capture started.', flush=True)
                if capture == 'tun':
                    previous = inbound_bytes(session, 'yukiwire-tun')
                    assert probe_https(port=None)['tls_verified']
                    wait_for(lambda: inbound_bytes(session, 'yukiwire-tun') > previous, 'HTTPS bypassed TUN')
                    print('TUN HTTPS and inbound counters passed.', flush=True)
                if capture == 'system' or combined:
                    proxy = WinInetProxy().read()
                    assert proxy['flags'] & 2 and proxy['server'] == session.own_proxy()
                    previous = inbound_bytes(session, 'local-http')
                    assert probe_https(port=session.endpoints['http'].port)['tls_verified']
                    wait_for(lambda: inbound_bytes(session, 'local-http') > previous, 'HTTP listener was bypassed')
                    print('HTTP proxy and inbound counters passed.', flush=True)
                if protection:
                    if capture == 'system':
                        assert not direct_tcp(), 'Direct traffic bypassed protection'
                    core = session.core.process
                    terminate_owned(core.pid, core.started)
                    wait_for(lambda: core.poll() is not None, 'Core exit was not reported')
                    session.stop()
                    assert session.protection.active
                    assert not direct_tcp(), 'Traffic leaked after core death'
                    session.protection.release(session.broker)
                    wait_for(direct_tcp, 'Explicit protection release did not restore network')
                else:
                    session.stop()
                assert WinInetProxy().read() == before_proxy, 'System proxy was not restored'
                assert foreign_snapshot() == before_foreign, 'Foreign network state changed'
                assert not (STATE / 'network-lease.dpapi').exists()
                print('Capture, traffic counters, stop/recovery: passed', flush=True)
            finally:
                try:
                    session.stop()
                finally:
                    session.protection.release(session.broker)
                    if session.broker:
                        session.broker.close()

        print('Live helper EOF with combined capture...', flush=True)
        session = Session()
        try:
            session.start(profile, dict(DEFAULTS, capture='tun', tun_system_proxy=True, preset='all'))
            record = session.guard.journal.read()
            core = session.core.process
            session.broker.close()
            wait_for(lambda: process_identity(core.pid) != core.started, 'Core survived helper EOF')
            wait_for(lambda: tun_clean(record), 'TUN survived helper EOF')
            session.stop()
            assert WinInetProxy().read() == before_proxy
            assert foreign_snapshot() == before_foreign
        finally:
            session.stop()
            session.broker.close()
        print('Production TUN/system/combined, WFP core crash/release and EOF recovery passed.', flush=True)
    finally:
        peer.close()


if __name__ == '__main__':
    verify()
