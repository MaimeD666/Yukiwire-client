"""Real process routing on isolated loopback ports; no system proxy or TUN changes."""
from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
from socketserver import BaseRequestHandler, ThreadingUDPServer
import struct
import sys
import threading
import time
import unittest

from yukiwire.config import build_config
from yukiwire.health import diagnostic_config
from yukiwire.paths import CORE
from yukiwire.process import CoreProcess
from yukiwire.routing import DEFAULTS, apply_routing


@contextmanager
def running_core(config):
    # Reserve distinct ephemeral ports without ever using the application's ports.
    reservations = []
    try:
        for inbound in config['inbounds']:
            reservation = socket.socket()
            reservations.append(reservation)
            reservation.bind(('127.0.0.1', 0))
            inbound['port'] = reservation.getsockname()[1]
        ports = {inbound['tag']: inbound['port'] for inbound in config['inbounds']}
    finally:
        for reservation in reservations:
            reservation.close()
    core = CoreProcess(CORE, config)
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.create_connection(('127.0.0.1', ports['local-http']), timeout=.2):
                    break
            except OSError:
                if core.process.poll() is not None or time.monotonic() >= deadline:
                    raise AssertionError('Isolated core did not start: ' + str(core.diagnostics()))
                time.sleep(.03)
        yield ports
    finally:
        core.close()


@contextmanager
def serving(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def read_exact(connection, length):
    result = b''
    while len(result) < length:
        data = connection.recv(length - len(result))
        if not data:
            raise AssertionError('SOCKS connection closed early')
        result += data
    return result


@unittest.skipUnless(CORE.is_file() and sys.platform == 'win32', 'Windows Xray integration')
class GameIntegrationTests(unittest.TestCase):
    def test_selected_process_bypasses_vpn_while_other_apps_and_checks_keep_vpn(self):
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
                self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nvpn')
                self.wfile.flush()

            def log_message(self, *args):
                pass

        process = Path(sys.executable)
        cases = [({'game_processes': process.name}, b'direct'),
                 ({'game_processes': process.as_posix()}, b'direct'),
                 ({'game_processes': 'unselected-game.exe'}, b'vpn'),
                 ({'game_processes': process.name, 'game_mode': False}, b'vpn'),
                 ({'game_processes': process.name, 'block': '127.0.0.1'}, None)]
        with serving(ThreadingHTTPServer(('127.0.0.1', 0), Origin)) as origin, \
             serving(ThreadingHTTPServer(('127.0.0.1', 0), Peer)) as peer:
            profile = json.dumps({'outbounds': [{'tag': 'proxy', 'protocol': 'http', 'settings': {
                'servers': [{'address': '127.0.0.1', 'port': peer.server_port}]}}]})
            for overrides, expected in cases:
                with self.subTest(overrides=overrides):
                    _, config = build_config(profile)
                    settings = dict(DEFAULTS, preset='all', proxy='127.0.0.1', game_mode=True)
                    settings.update(overrides)
                    config = diagnostic_config(apply_routing(config, settings))
                    with running_core(config) as ports:
                        for tag, wanted in [('local-http', expected), ('yukiwire-check', b'vpn')]:
                            connection = http.client.HTTPConnection('127.0.0.1', ports[tag], timeout=2)
                            try:
                                try:
                                    connection.request('GET', f'http://127.0.0.1:{origin.server_port}/')
                                    body = connection.getresponse().read()
                                except (OSError, http.client.HTTPException):
                                    body = None
                                if wanted is None:
                                    self.assertNotIn(body, (b'direct', b'vpn'))
                                else:
                                    self.assertEqual(body, wanted)
                            finally:
                                connection.close()

    def test_udp_game_process_bypasses_fallback_but_not_explicit_block(self):
        class Echo(BaseRequestHandler):
            def handle(self):
                data, connection = self.request
                connection.sendto(data, self.client_address)

        process = Path(sys.executable).name
        cases = [({'game_processes': process}, True),
                 ({'game_processes': 'unselected-game.exe'}, False),
                 ({'game_processes': process, 'game_mode': False}, False),
                 ({'game_processes': process, 'block': '127.0.0.1'}, False)]
        with serving(ThreadingUDPServer(('127.0.0.1', 0), Echo)) as origin:
            for overrides, expected in cases:
                with self.subTest(overrides=overrides):
                    _, config = build_config('{"outbounds":[{"tag":"proxy","protocol":"blackhole"}]}')
                    config['inbounds'][0]['settings']['udp'] = True
                    settings = dict(DEFAULTS, preset='all', proxy='127.0.0.1', game_mode=True)
                    settings.update(overrides)
                    with running_core(apply_routing(config, settings)) as ports, \
                         socket.create_connection(('127.0.0.1', ports['local-socks']), timeout=2) as control, \
                         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                        datagram.bind(('127.0.0.1', 0))
                        datagram.settimeout(1)
                        control.sendall(b'\x05\x01\x00')
                        self.assertEqual(read_exact(control, 2), b'\x05\x00')
                        control.sendall(b'\x05\x03\x00\x01' + socket.inet_aton('127.0.0.1') +
                                        struct.pack('!H', datagram.getsockname()[1]))
                        self.assertEqual(read_exact(control, 4), b'\x05\x00\x00\x01')
                        relay_ip = socket.inet_ntoa(read_exact(control, 4))
                        relay_port = struct.unpack('!H', read_exact(control, 2))[0]
                        payload = b'yukiwire-game-udp'
                        packet = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', origin.server_address[1]) + payload
                        datagram.sendto(packet, (relay_ip, relay_port))
                        if expected:
                            self.assertEqual(datagram.recv(4096)[10:], payload)
                        else:
                            with self.assertRaises(socket.timeout):
                                datagram.recv(4096)
