import ctypes
import ipaddress
import os
import unittest
from unittest.mock import patch

from yukiwire.network import inspect_tun
from yukiwire.windows_snapshot import adapters, routes, Route, RouteTable, foreign_capture_present


class TunInspectionTests(unittest.TestCase):
    def setUp(self):
        self.identity = {'adapter': 'Yukiwire-012345abcdef', 'description': 'Yukiwire 012345abcdef'}
        self.adapter = {'index': 123, 'index6': 123, 'name': self.identity['adapter'],
                        'description': self.identity['description'] + ' Tunnel', 'up': True,
                        'addresses': ['172.29.250.1/30', 'fd72:756b:6977::1/126'], 'dns': ['172.29.250.2']}
        self.table = [{'index': 123, 'metric': 0, 'prefix': value, 'next_hop': '::' if ':' in value else '0.0.0.0'}
                      for value in ('0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1')]

    def ready(self):
        with patch('yukiwire.windows_snapshot.adapters', return_value=[self.adapter]), \
             patch('yukiwire.windows_snapshot.routes', return_value=self.table):
            return inspect_tun('Ready', self.identity)['ready']

    def test_complete_owned_tun_is_ready(self):
        self.assertTrue(self.ready())

    def test_routes_alone_cannot_claim_readiness(self):
        self.adapter['addresses'] = ['172.29.250.1/30']
        self.assertFalse(self.ready())

    def test_wrong_dns_cannot_claim_readiness(self):
        self.adapter['dns'] = ['192.168.1.1']
        self.assertFalse(self.ready())

    def test_missing_ipv6_route_cannot_claim_readiness(self):
        self.table.pop()
        self.assertFalse(self.ready())

    def test_foreign_interface_routes_do_not_count(self):
        self.table[-1]['index'] = 999
        self.assertFalse(self.ready())

    def test_foreign_adapter_description_is_rejected(self):
        self.adapter['description'] = 'Another client Tunnel'
        with self.assertRaises(ValueError):
            self.ready()

    def test_unknown_vpn_is_detected_from_actual_split_routes(self):
        snapshot = {'adapters': [{'kind': 6, 'up': True, 'index': 123, 'index6': 123}], 'routes': self.table}
        with patch('yukiwire.windows_snapshot.foreign_snapshot', return_value=snapshot):
            self.assertTrue(foreign_capture_present())

    def test_vpn_default_route_via_gateway_is_not_missed(self):
        for kind, description in ((23, 'PPP'), (131, 'Tunnel'), (6, 'WireGuard Tunnel')):
            snapshot = {'adapters': [{'kind': kind, 'description': description, 'up': True, 'index': 123, 'index6': 123}],
                        'routes': [{'index': 123, 'prefix': '0.0.0.0/0', 'next_hop': '10.8.0.1'}]}
            with self.subTest(kind=kind), patch('yukiwire.windows_snapshot.foreign_snapshot', return_value=snapshot):
                self.assertTrue(foreign_capture_present())

    def test_ordinary_ethernet_gateway_is_not_a_vpn(self):
        snapshot = {'adapters': [{'kind': 6, 'description': 'Ethernet', 'up': True, 'index': 1, 'index6': 1}],
                    'routes': [{'index': 1, 'prefix': '0.0.0.0/0', 'next_hop': '192.168.1.1'}]}
        with patch('yukiwire.windows_snapshot.foreign_snapshot', return_value=snapshot):
            self.assertFalse(foreign_capture_present())


@unittest.skipUnless(os.name == 'nt', 'Windows IP Helper required')
class SnapshotIntegrationTests(unittest.TestCase):
    def test_read_only_ipv4_ipv6_snapshot_has_valid_native_structure(self):
        self.assertEqual(ctypes.sizeof(Route), 104)
        self.assertEqual(RouteTable.first.offset, 8)
        entries = adapters()
        table = routes()
        self.assertGreater(len(entries), 0)
        self.assertGreater(len(table), 0)
        indexes = {index for item in entries for index in (item['index'], item['index6'])}
        for item in entries:
            for address in item['addresses']:
                ipaddress.ip_interface(address)
            for server in item['dns']:
                ipaddress.ip_address(server)
        for route in table:
            self.assertIn(route['index'], indexes)
            ipaddress.ip_network(route['prefix'])
            ipaddress.ip_address(route['next_hop'])
            self.assertGreaterEqual(route['metric'], 0)
