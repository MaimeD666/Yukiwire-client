"""Actual Hysteria2 TCP/UDP and TLS rejection; loopback only, no OS capture."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
from socketserver import BaseRequestHandler, ThreadingUDPServer
import struct
import unittest

from hysteria_fixture import hysteria_peer
from test_game_integration import read_exact, running_core, serving
from yukiwire.config import build_config
from yukiwire.paths import CORE
from yukiwire.routing import DEFAULTS, apply_routing
from yukiwire.session import validate_config


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', '11')
        self.end_headers()
        self.wfile.write(b'hysteria-ok')

    def log_message(self, *args):
        pass


class Echo(BaseRequestHandler):
    def handle(self):
        data, connection = self.request
        connection.sendto(data, self.client_address)


def client_config(profile):
    _, config = build_config(profile)
    # Force even loopback through the VPN so direct routing cannot pass the test.
    return apply_routing(config, dict(DEFAULTS, preset='all', proxy='127.0.0.1'))


def get_http(port, origin):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
    try:
        connection.request('GET', 'http://127.0.0.1:%s/' % origin.server_port)
        return connection.getresponse().read()
    except (OSError, http.client.HTTPException):
        return None
    finally:
        connection.close()


@unittest.skipUnless(CORE.is_file(), 'Install Xray for real Hysteria2 checks')
class HysteriaIntegrationTests(unittest.TestCase):
    def test_tcp_with_and_without_salamander_and_hopping(self):
        with serving(ThreadingHTTPServer(('127.0.0.1', 0), Origin)) as origin:
            for obfs in (False, True):
                with self.subTest(obfs=obfs), hysteria_peer(CORE, obfs) as profile:
                    for hopping in (False, True):
                        # A one-port range exercises the real UDP-hop wrapper deterministically.
                        link = profile
                        if hopping:
                            port = profile.split('127.0.0.1:', 1)[1].split('/', 1)[0]
                            link = profile.replace(':%s/' % port, ':%s,%s/' % (port, port))
                        with self.subTest(hopping=hopping):
                            config = client_config(link)
                            validate_config(config)
                            with running_core(config) as ports:
                                self.assertEqual(get_http(ports['local-http'], origin), b'hysteria-ok')

    def test_udp_through_hysteria_and_salamander(self):
        with serving(ThreadingUDPServer(('127.0.0.1', 0), Echo)) as origin, hysteria_peer(CORE, True) as profile:
            config = client_config(profile)
            config['inbounds'][0]['settings']['udp'] = True  # Isolated test SOCKS only.
            with running_core(config) as ports, \
                 socket.create_connection(('127.0.0.1', ports['local-socks']), timeout=3) as control, \
                 socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                datagram.bind(('127.0.0.1', 0))
                datagram.settimeout(5)
                control.sendall(b'\x05\x01\x00')
                self.assertEqual(read_exact(control, 2), b'\x05\x00')
                control.sendall(b'\x05\x03\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', datagram.getsockname()[1]))
                self.assertEqual(read_exact(control, 4), b'\x05\x00\x00\x01')
                relay = socket.inet_ntoa(read_exact(control, 4)), struct.unpack('!H', read_exact(control, 2))[0]
                packet = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', origin.server_address[1]) + b'hy2-udp'
                datagram.sendto(packet, relay)
                self.assertEqual(datagram.recv(1024), packet)

    def test_wrong_pin_and_password_fail_without_direct_fallback(self):
        with serving(ThreadingHTTPServer(('127.0.0.1', 0), Origin)) as origin, hysteria_peer(CORE) as profile:
            for link in (profile.split('&pinSHA256=')[0] + '&pinSHA256=' + '00' * 32,
                         profile.replace('user%3Afixture', 'wrong-password')):
                with running_core(client_config(link)) as ports:
                    self.assertNotEqual(get_http(ports['local-http'], origin), b'hysteria-ok')
