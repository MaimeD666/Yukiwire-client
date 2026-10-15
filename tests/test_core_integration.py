import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
import unittest
from yukiwire.backend import Session, validate_config
from yukiwire.config import build_config
from yukiwire.routing import apply_routing
from yukiwire.network import add_tun, new_tun
from yukiwire.telemetry import enable_metrics
from yukiwire.paths import CORE
from yukiwire.routing import DEFAULTS


@unittest.skipUnless(CORE.is_file(), 'Install Xray for real-core integration checks')
class CoreIntegrationTests(unittest.TestCase):
    def test_hysteria2_kcp_and_userspace_wireguard_are_accepted_by_pinned_core(self):
        import base64
        wireguard = json.dumps({'outbounds': [{'tag': 'proxy', 'protocol': 'wireguard', 'settings': {
            'secretKey': base64.b64encode(bytes(range(32))).decode(), 'address': ['10.0.0.2/32'],
            'peers': [{'publicKey': base64.b64encode(bytes(range(32, 64))).decode(), 'endpoint': '192.0.2.1:51820'}]}}]})
        for profile in ('hy2://fixture@192.0.2.1:443?sni=server.example.com&obfs=salamander&obfs-password=fixture',
                        'vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?type=kcp', wireguard):
            with self.subTest(protocol=profile.split(':', 1)[0]):
                _, config = build_config(profile)
                validate_config(apply_routing(config, dict(DEFAULTS, preset='all')))

    def test_user_rule_priority_is_enforced_by_real_core(self):
        counters = {'direct': 0, 'profile': 0}
        class Origin(BaseHTTPRequestHandler):
            def do_GET(self):
                counters['direct'] += 1
                self.send_response(200)
                self.send_header('Content-Length', '6')
                self.end_headers()
                self.wfile.write(b'direct')
            def log_message(self, *args):
                pass
        class Peer(BaseHTTPRequestHandler):
            def do_CONNECT(self):
                counters['profile'] += 1
                self.send_response(200)
                self.end_headers()
                while self.rfile.readline() not in (b'\r\n', b'\n', b''):
                    pass
                self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nprofile')
                self.wfile.flush()
            def log_message(self, *args):
                pass
        origin, peer = HTTPServer(('127.0.0.1', 0), Origin), HTTPServer(('127.0.0.1', 0), Peer)
        for server in (origin, peer):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        profile = json.dumps({'outbounds': [{'tag': 'profile', 'protocol': 'http', 'settings': {
            'servers': [{'address': '127.0.0.1', 'port': peer.server_port}]}}]})
        try:
            for overrides, expected in (({}, b'direct'), ({'proxy': '127.0.0.1'}, b'profile'),
                                         ({'proxy': '127.0.0.1', 'direct': '127.0.0.1'}, b'profile'),
                                         ({'proxy': '127.0.0.1', 'direct': '127.0.0.1', 'block': '127.0.0.1'}, None)):
                with self.subTest(overrides=overrides):
                    session = Session()
                    previous = dict(counters)
                    connection = None
                    try:
                        session.start(profile, dict(DEFAULTS, preset='ru-direct', auto_reconnect=False, **overrides))
                        connection = http.client.HTTPConnection('127.0.0.1', session.endpoints['http'].port, timeout=3)
                        try:
                            connection.request('GET', 'http://127.0.0.1:%s/' % origin.server_port)
                            body = connection.getresponse().read()
                        except (OSError, http.client.HTTPException):
                            body = None
                        if expected is None:
                            self.assertNotIn(body, (b'direct', b'profile'))
                            self.assertEqual(counters, previous)
                        else:
                            self.assertEqual(body, expected)
                    finally:
                        if connection:
                            connection.close()
                        session.stop()
        finally:
            for server in (origin, peer):
                server.shutdown()
                server.server_close()

    def test_diagnostic_port_actually_uses_profile_when_normal_route_is_direct(self):
        class Origin(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', '6')
                self.end_headers()
                self.wfile.write(b'direct')
            def log_message(self, *args):
                pass
        class Peer(BaseHTTPRequestHandler):
            def do_CONNECT(self):
                self.send_response(200)
                self.end_headers()
                while self.rfile.readline() not in (b'\r\n', b'\n', b''):
                    pass
                self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nprofile')
                self.wfile.flush()
            def log_message(self, *args):
                pass
        origin = HTTPServer(('127.0.0.1', 0), Origin)
        peer = HTTPServer(('127.0.0.1', 0), Peer)
        for server in (origin, peer):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        session = Session()
        try:
            profile = json.dumps({'outbounds': [{'tag': 'profile', 'protocol': 'http', 'settings': {'servers': [{'address': '127.0.0.1', 'port': peer.server_port}]}}]})
            session.start(profile, dict(DEFAULTS, preset='selected', proxy='never.used.invalid', auto_reconnect=False))
            for key, expected in (('http', b'direct'), ('probe', b'profile')):
                endpoint = session.endpoints[key]
                connection = http.client.HTTPConnection('127.0.0.1', endpoint.port, timeout=3)
                try:
                    target = 'http://example.com:443/' if key == 'probe' else 'http://127.0.0.1:%s/' % origin.server_port
                    connection.request('GET', target, headers=endpoint.headers)
                    self.assertEqual(connection.getresponse().read(), expected)
                finally:
                    connection.close()
        finally:
            session.stop()
            for server in (origin, peer):
                server.shutdown()
                server.server_close()

    def test_tun_config_validates_without_starting_an_adapter(self):
        # Pinned Xray creates devices in Handler.Start, not during run -test.
        _, config = build_config('vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls')
        config = add_tun(enable_metrics(apply_routing(config, DEFAULTS)), new_tun())
        validate_config(config)

    def test_split_dns_tun_validates_with_named_doh_and_ipv6_direct_dns(self):
        _, config = build_config('vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls')
        settings = dict(DEFAULTS, capture='tun', dns_vpn='https://dns.example/dns-query', direct='cdn.example', proxy='proxy.example', block='blocked.example')
        config = add_tun(enable_metrics(apply_routing(config, settings)), new_tun(), settings, ['192.0.2.53', '2001:db8::53'])
        validate_config(config)

    def test_game_tun_config_validates_and_keeps_dns_via_vpn(self):
        _, config = build_config('vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls')
        config = add_tun(enable_metrics(apply_routing(config, dict(DEFAULTS, game_mode=True,
                         game_processes='dota2.exe\ncs2.exe\nC:/Games/My Game/Game.exe'))), new_tun())
        self.assertEqual(config['routing']['rules'][0]['inboundTag'], ['yukiwire-dns'])
        self.assertEqual(config['routing']['rules'][0]['outboundTag'], 'proxy')
        self.assertEqual(config['routing']['rules'][1]['port'], '53')
        validate_config(config)

    def test_local_route_and_actual_traffic_counters(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                data = b'yukiwire-local-fixture' * 256
                self.send_response(200)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            def log_message(self, *args):
                pass
        fixture = HTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=fixture.serve_forever, daemon=True).start()
        session = Session()
        try:
            session.start('vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls', dict(DEFAULTS, auto_reconnect=False))
            connection = http.client.HTTPConnection('127.0.0.1', session.endpoints['http'].port, timeout=5)
            try:
                connection.request('GET', 'http://127.0.0.1:%s/' % fixture.server_port)
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertIn(b'yukiwire-local-fixture', response.read())
            finally:
                connection.close()
            stats = session.telemetry.sample()
            self.assertGreater(stats['download_bytes'], 0)
            self.assertGreater(stats['upload_bytes'], 0)
            self.assertGreater(stats['direct_bytes'], 0)
        finally:
            session.stop()
            fixture.shutdown()
            fixture.server_close()
