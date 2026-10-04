import unittest
from yukiwire.config import build_config
from yukiwire.routing import DEFAULTS, apply_routing, explain, parse_rules


class RoutingTests(unittest.TestCase):
    def test_forced_vpn_wins_over_ru_and_direct_suffix(self):
        options = dict(DEFAULTS, proxy='blocked.ru', direct='ru')
        self.assertEqual(explain('sub.blocked.ru', options)['route'], 'Через VPN')
        _, config = build_config('vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls')
        routed = apply_routing(config, options, {'ru-blocked': 'geosite:ru-blocked'})
        rules = routed['routing']['rules']
        self.assertEqual(rules[0]['domain'], ['domain:blocked.ru'])
        self.assertEqual(rules[0]['outboundTag'], 'proxy')
        self.assertEqual(rules[-1]['outboundTag'], 'proxy')

    def test_block_rule_wins_over_vpn(self):
        result = explain('example.com', dict(DEFAULTS, block='example.com', proxy='example.com'))
        self.assertEqual(result['route'], 'Блокировать')

    def test_ip_and_unicode_domains(self):
        domains, ips = parse_rules('https://пример.рф/path\n*.example.com\n192.0.2.34/24\n2001:db8::1')
        self.assertIn('xn--e1afmkfd.xn--p1ai', domains)
        self.assertIn('192.0.2.0/24', ips)
        self.assertIn('2001:db8::1/128', ips)

    def test_selected_preset_needs_a_selection(self):
        _, config = build_config('{"outbounds":[{"tag":"server","protocol":"vless","settings":{}}]}')
        with self.assertRaises(ValueError):
            apply_routing(config, dict(DEFAULTS, preset='selected'))

    def test_original_json_is_preserved(self):
        _, config = build_config('{"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","domain":["domain:example.com"],"outboundTag":"direct"}]}}')
        routed = apply_routing(config, dict(DEFAULTS, preset='original'))
        self.assertEqual(routed['routing'], config['routing'])
        self.assertEqual(routed['outbounds'], config['outbounds'])

    def test_private_traffic_is_local_by_default(self):
        self.assertEqual(explain('192.168.1.1', DEFAULTS)['route'], 'Напрямую')
        self.assertEqual(explain('printer.local', DEFAULTS)['route'], 'Напрямую')

    def test_original_json_does_not_promise_direct_private_routes(self):
        for target in ('192.168.1.1', '::1', 'printer.local', 'localhost'):
            with self.subTest(target=target):
                result = explain(target, dict(DEFAULTS, preset='original'))
                self.assertEqual(result['route'], 'По JSON')
                self.assertFalse(result['definitive'])

    def test_invalid_cidr_is_not_silently_a_domain(self):
        with self.assertRaises(ValueError):
            parse_rules('192.168.1.0/99')
