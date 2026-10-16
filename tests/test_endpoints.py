import http.client
import socket
import unittest

from yukiwire.backend import Session
from yukiwire.endpoints import allocate_endpoints, configure_local
from yukiwire.paths import CORE
from yukiwire.routing import DEFAULTS


class EndpointTests(unittest.TestCase):
    def test_pure_tun_has_no_general_proxy_and_combined_keeps_both(self):
        endpoints = allocate_endpoints()
        pure = configure_local({}, endpoints, dict(DEFAULTS, capture='tun'))
        self.assertEqual(pure['inbounds'], [])
        combined = configure_local({}, endpoints, dict(DEFAULTS, capture='tun', tun_system_proxy=True))
        self.assertEqual({i['tag'] for i in combined['inbounds']}, {'local-http', 'local-socks'})
        self.assertEqual(combined['inbounds'][1]['settings']['auth'], 'password')
        self.assertNotIn(endpoints['socks'].password, repr(endpoints))

    @unittest.skipUnless(CORE.is_file(), 'Install Xray for endpoint authentication checks')
    def test_real_core_rejects_unauthenticated_diagnostics_metrics_and_socks(self):
        session = Session()
        try:
            session.start('{"outbounds":[{"protocol":"blackhole"}]}', dict(DEFAULTS, preset='all'))
            for name in ('probe', 'metrics'):
                endpoint = session.endpoints[name]
                for headers in ({}, {'Proxy-Authorization': 'Basic YmFkOmJhZA=='}):
                    with self.subTest(endpoint=name, credentials=bool(headers)):
                        connection = http.client.HTTPConnection('127.0.0.1', endpoint.port, timeout=2)
                        try:
                            connection.request('GET', 'http://metrics.internal/debug/vars', headers=headers)
                            self.assertEqual(connection.getresponse().status, 407)
                        finally:
                            connection.close()
            # An authenticated metrics client gets counters without a subprocess.
            self.assertGreaterEqual(session.telemetry.sample()['download_bytes'], 0)
            endpoint = session.endpoints['socks']
            with socket.create_connection(('127.0.0.1', endpoint.port), timeout=2) as control:
                control.sendall(b'\x05\x01\x00')
                self.assertEqual(control.recv(2), b'\x05\xff')
            with socket.create_connection(('127.0.0.1', endpoint.port), timeout=2) as control:
                control.sendall(b'\x05\x01\x02')
                self.assertEqual(control.recv(2), b'\x05\x02')
                user, password = endpoint.username.encode(), endpoint.password.encode()
                control.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
                self.assertEqual(control.recv(2), b'\x01\x00')
        finally:
            session.stop()
