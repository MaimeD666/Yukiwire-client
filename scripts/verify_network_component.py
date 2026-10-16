"""Opt-in UAC/installation/IPC test. Never sends start or creates a TUN adapter."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))


def verify():
    from build_network import build
    from yukiwire.broker import Broker
    from yukiwire.config import build_config
    from yukiwire.endpoints import allocate_endpoints, configure_local
    from yukiwire.health import diagnostic_config
    from yukiwire.network import add_tun, process_identity, WinInetProxy
    from yukiwire.routing import DEFAULTS, apply_routing
    from yukiwire.telemetry import enable_metrics
    from yukiwire.windows_snapshot import adapters, routes
    from yukiwire.paths import RUNTIME
    import json
    import time

    print('Building protected component...', flush=True)
    build()
    before_proxy = WinInetProxy().read()
    before_adapters = adapters()
    before_routes = routes()
    _, config = build_config('vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls')
    settings = dict(DEFAULTS, capture='tun', tun_system_proxy=True, preset='all')
    endpoints = allocate_endpoints()
    config = apply_routing(config, settings)
    config = configure_local(config, endpoints, settings)
    config = diagnostic_config(enable_metrics(config, endpoints['metrics']), endpoints['probe'])
    config = add_tun(config, dict(adapter='Yukiwire-000000000000', description='Yukiwire 000000000000'))
    print('Installing/connecting protected helper...', flush=True)
    broker = Broker()
    print('Production IPC connected.', flush=True)
    pending = None
    try:
        for attempt in range(2):
            print('Preparing core, attempt %d...' % (attempt + 1), flush=True)
            pending = broker.request('prepare', config=json.dumps(config), assets=str(RUNTIME))
            assert process_identity(pending['pid']) == pending['core_start'], 'Prepared core identity mismatch'
            assert pending['adapter'] != 'Yukiwire-000000000000', 'Helper must choose its own adapter identity'
            if attempt:
                assert broker.request('stop', serial=pending['serial'] - 1) is False, 'Stale stop must be ignored'
                assert process_identity(pending['pid']) == pending['core_start'], 'Stale stop killed the new core'
            assert WinInetProxy().read() == before_proxy, 'Proxy changed before configuration was supplied'
            assert adapters() == before_adapters and routes() == before_routes, 'Network changed during prepare'
            broker.request('stop', serial=pending['serial'])
            print('Prepared core stopped.', flush=True)
            assert process_identity(pending['pid']) != pending['core_start'], 'Core survived stop'
        pending = broker.request('prepare', config=json.dumps(config), assets=str(RUNTIME))
    finally:
        # IPC EOF must stop even a prepared core whose config was never delivered.
        broker.close()
    deadline = time.monotonic() + 10
    while pending and process_identity(pending['pid']) == pending['core_start'] and time.monotonic() < deadline:
        time.sleep(.1)
    assert pending and process_identity(pending['pid']) != pending['core_start'], 'Core survived pipe EOF'
    assert WinInetProxy().read() == before_proxy
    assert adapters() == before_adapters and routes() == before_routes
    print('Protected installation, UAC, peer identity, prepare/stop, stale stop and EOF passed; no network capture started.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--install', action='store_true', help='Allow installing the protected component and requesting UAC')
    if not parser.parse_args().install:
        parser.error('--install is required; this test installs a component in Program Files')
    verify()
