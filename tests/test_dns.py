import socket
import threading
import time
import unittest
from unittest.mock import patch

from yukiwire.config import build_config
from yukiwire.dns_config import configure_tun_dns, system_servers
from yukiwire.network import add_tun, new_tun
from yukiwire.paths import CORE
from yukiwire.process import CoreProcess
from yukiwire.routing import DEFAULTS, apply_routing, normalize_settings


def configuration():
    _, config = build_config('vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls')
    settings = dict(DEFAULTS, capture='tun', preset='ru-direct', direct='direct.example\noverlap.ru',
                    proxy='proxy.example\noverlap.ru', block='blocked.example')
    return apply_routing(config, settings), settings


class DnsTests(unittest.TestCase):
    def test_split_policy_preserves_domain_rule_order_and_limits_fallback(self):
        config, settings = configuration()
        configure_tun_dns(config, settings, 'proxy', ['192.0.2.53'])
        servers = config['dns']['servers']
        self.assertEqual(servers[0]['domains'], ['domain:proxy.example', 'domain:overlap.ru'])
        self.assertEqual(servers[0]['tag'], 'yukiwire-dns')
        self.assertEqual(servers[1]['tag'], 'yukiwire-dns-direct')
        self.assertEqual(config['dns']['hosts']['domain:blocked.example'], ['0.0.0.0', '::'])
        self.assertTrue(all(server['finalQuery'] for server in servers))
        self.assertEqual(servers[-1]['address'], DEFAULTS['dns_vpn'])
        self.assertNotIn('domains', servers[-1])

    def test_all_vpn_dns_uses_custom_resolver_without_physical_dns_scan(self):
        config, settings = configuration()
        settings.update(dns='doh', dns_vpn='https://1.0.0.1/dns-query')
        with patch('yukiwire.dns_config.system_servers') as scan:
            add_tun(config, new_tun(), settings)
        scan.assert_not_called()
        self.assertEqual(config['dns']['servers'], ['https://1.0.0.1/dns-query'])

    def test_dns_configuration_rejects_loops_and_unprotected_urls(self):
        for changes in ({'dns_direct': '172.29.250.2'}, {'dns_direct': 'not-an-ip'},
                        {'dns_vpn': 'http://dns.example/query'}, {'dns_vpn': 'https://user:secret@dns.example/query'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError): normalize_settings(dict(DEFAULTS, **changes))

    def test_named_doh_bootstrap_is_limited_to_its_own_name(self):
        config, settings = configuration()
        settings.update(dns='doh', dns_vpn='https://dns.example/dns-query')
        configure_tun_dns(config, settings, 'proxy', ['192.0.2.53'])
        bootstrap = config['dns']['servers'][0]
        self.assertEqual(bootstrap['domains'], ['full:dns.example'])
        self.assertTrue(bootstrap['skipFallback'])
        self.assertTrue(bootstrap['finalQuery'])
        self.assertEqual(config['routing']['rules'][0]['outboundTag'], 'yukiwire-direct')
        self.assertEqual(config['dns']['servers'][1], settings['dns_vpn'])

    def test_system_dns_snapshot_excludes_tun_and_inactive_adapters(self):
        records = [{'name': 'Ethernet', 'index': 1, 'index6': 1, 'up': True, 'dns': ['192.0.2.53']},
                   {'name': 'Yukiwire-0123456789ab', 'index': 2, 'index6': 2, 'up': True, 'dns': ['172.29.250.2']},
                   {'name': 'Offline', 'index': 3, 'index6': 3, 'up': False, 'dns': ['192.0.2.54']}]
        with patch('yukiwire.windows_snapshot.adapters', return_value=records), \
             patch('yukiwire.windows_snapshot.routes', return_value=[{'index': i, 'prefix': '0.0.0.0/0'} for i in (1, 2, 3)]):
            self.assertEqual(system_servers(), ['192.0.2.53'])

    @unittest.skipUnless(CORE.is_file(), 'Install pinned Xray')
    def test_real_core_dns_obeys_direct_proxy_block_and_overlap(self):
        peers, received = [], [[], []]
        stop = threading.Event()
        def serve(peer, index):
            while not stop.is_set():
                try: packet, address = peer.recvfrom(4096)
                except socket.timeout: continue
                except OSError: return
                received[index].append(packet)
                response = packet[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + packet[12:]
                response += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04' + bytes((192, 0, 2, 10 + index))
                peer.sendto(response, address)
        for index in range(2):
            peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); peer.bind(('127.0.0.1', 0)); peer.settimeout(.2)
            peers.append(peer); threading.Thread(target=serve, args=(peer, index), daemon=True).start()
        core = None
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            config, settings = configuration()
            configure_tun_dns(config, settings, 'proxy', ['192.0.2.53'])
            # Exercise DNS selection with both local UDP fixtures. No Internet/TUN
            # or TLS exception is involved; all other policy fields are unchanged.
            for server in config['dns']['servers']:
                index = 0 if server['tag'] == 'yukiwire-dns-direct' else 1
                server.update(address='127.0.0.1', port=peers[index].getsockname()[1])
            config['outbounds'][0] = {'tag': 'proxy', 'protocol': 'freedom', 'settings': {}}
            config['outbounds'].append({'tag': 'dns-out', 'protocol': 'dns'})
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
                reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]
            config['inbounds'] = [{'tag': 'dns-input', 'listen': '127.0.0.1', 'port': port,
                                   'protocol': 'dokodemo-door', 'settings': {'address': '127.0.0.1', 'port': 53, 'network': 'udp'}}]
            config['routing']['rules'].insert(0, {'type': 'field', 'inboundTag': ['dns-input'], 'outboundTag': 'dns-out'})
            core = CoreProcess(CORE, config)
            client.settimeout(.5)
            for domain, expected in [('direct.example', 0), ('proxy.example', 1), ('overlap.ru', 1), ('cdn.ru', 0), ('outside.example', 1), ('blocked.example', None)]:
                packet = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + b''.join(bytes([len(label)]) + label.encode() for label in domain.split('.')) + b'\x00\x00\x01\x00\x01'
                before = [len(items) for items in received]
                deadline = time.monotonic() + 4
                while True:
                    client.sendto(packet, ('127.0.0.1', port))
                    try: response, _ = client.recvfrom(4096); break
                    except (socket.timeout, ConnectionResetError):
                        if time.monotonic() >= deadline: raise
                        time.sleep(.05)
                with self.subTest(domain=domain):
                    if expected is None:
                        self.assertEqual([len(items) for items in received], before)
                    else:
                        self.assertGreater(len(received[expected]), before[expected])
                        self.assertEqual(len(received[1 - expected]), before[1 - expected])
                        self.assertEqual(response[-4:], bytes((192, 0, 2, 10 + expected)))
        finally:
            if core: core.close()
            stop.set(); client.close()
            for peer in peers: peer.close()
