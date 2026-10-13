import unittest
from yukiwire.config import build_config
from yukiwire.routing import DEFAULTS, apply_routing, explain, normalize_settings, parse_game_processes, parse_rules


class RoutingTests(unittest.TestCase):
    def test_russian_ip_detection_only_changes_the_russian_preset(self):
        _, config = build_config('vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls')
        tags = {'geoip-ru': 'geoip:ru', 'ru-blocked': 'geosite:ru-blocked'}
        for preset in ('all', 'selected', 'original'):
            settings = dict(DEFAULTS, preset=preset)
            self.assertEqual(apply_routing(config, settings, tags), apply_routing(config, dict(settings, ru_ip=True), tags))
        routed = apply_routing(config, dict(DEFAULTS, ru_ip=True), tags)
        self.assertEqual(routed['routing']['domainStrategy'], 'IPIfNonMatch')
        self.assertTrue(any(r.get('ip') == ['geoip:ru'] for r in routed['routing']['rules']))

    def test_tun_companion_proxy_is_explicit_and_does_not_change_routing(self):
        self.assertFalse(normalize_settings({'capture': 'tun'})['tun_system_proxy'])
        with self.assertRaises(ValueError):
            normalize_settings({'tun_system_proxy': 'true'})
        _, config = build_config('vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls')
        settings = dict(DEFAULTS, capture='tun', game_mode=True, proxy='youtube.com', direct='example.ru')
        self.assertEqual(apply_routing(config, settings), apply_routing(config, dict(settings, tun_system_proxy=True)))

    def test_game_settings_migrate_without_enabling_bypass(self):
        settings = normalize_settings({'preset': 'all', 'proxy': 'example.com'})
        self.assertFalse(settings['game_mode'])
        self.assertEqual(settings['game_processes'], 'dota2.exe')
        self.assertEqual(settings['proxy'], 'example.com')

    def test_game_executables_preserve_case_spaces_and_normalize_paths(self):
        self.assertEqual(parse_game_processes('dota2.exe\r\n"C:\\Games\\My Game\\Game.exe"\ndota2.exe\n'),
                         ['dota2.exe', 'C:/Games/My Game/Game.exe'])
        self.assertEqual(parse_game_processes('\\\\server\\Games\\Game.exe'), ['//server/Games/Game.exe'])

    def test_game_rules_reject_broad_or_malformed_matches(self):
        for value in ('*', '*.exe', 'self/', 'C:/Games/', '../game.exe', 'Games/game.exe',
                      'C:game.exe', '/game.exe', 'https://game.exe', 'dota2', '.exe', 'game.exe --flag',
                      'game\x00.exe', 'C:/Games/../game.exe', [], None, 'x' * 16385):
            with self.subTest(value=repr(value)[:50]), self.assertRaises(ValueError):
                parse_game_processes(value)
        with self.assertRaises(ValueError):
            parse_game_processes('\n'.join(f'game{i}.exe' for i in range(101)))

    def test_enabled_game_mode_requires_games_and_a_boolean(self):
        for overrides in ({'game_mode': True, 'game_processes': ''}, {'game_mode': 'true'}, {'game_mode': 1}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                normalize_settings(overrides)
        self.assertEqual(normalize_settings({'game_processes': ''})['game_processes'], '')

    def test_game_rule_keeps_other_routes_and_does_not_capture_service_traffic(self):
        _, config = build_config('vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls')
        for preset in ('all', 'ru-direct', 'selected'):
            with self.subTest(preset=preset):
                settings = dict(DEFAULTS, preset=preset, proxy='example.com', block='blocked.com\n192.0.2.5', direct='other.com')
                normal = apply_routing(config, settings)
                gaming = apply_routing(config, dict(settings, game_mode=True))
                rules = gaming['routing']['rules']
                game = next(rule for rule in rules if 'process' in rule)
                self.assertEqual(rules.index(game), 2)  # Both block rules still win.
                self.assertEqual(game['outboundTag'], 'yukiwire-direct')
                self.assertEqual(game['process'], ['dota2.exe'])
                self.assertEqual(game['inboundTag'], ['local-socks', 'local-http', 'yukiwire-tun'])
                self.assertEqual([r for r in rules if r is not game], normal['routing']['rules'])
                self.assertEqual(gaming['outbounds'], normal['outbounds'])
                self.assertEqual(apply_routing(config, dict(settings, game_mode=False)), normal)

    def test_game_explanation_preserves_blocks_and_other_apps_vpn(self):
        settings = dict(DEFAULTS, preset='all', game_mode=True, proxy='example.com', block='blocked.com')
        self.assertEqual(explain('example.com', settings, process='dota2.exe')['route'], 'Напрямую')
        self.assertEqual(explain('203.0.113.1', settings, process='dota2.exe')['route'], 'Напрямую')
        self.assertEqual(explain('example.com', settings, process='Discord.exe')['route'], 'Через VPN')
        self.assertEqual(explain('blocked.com', settings, process='dota2.exe')['route'], 'Блокировать')
        self.assertFalse(explain('example.com', settings)['definitive'])

    def test_game_explanation_matches_exact_executable_not_its_folder(self):
        settings = dict(DEFAULTS, preset='all', game_mode=True, game_processes='C:/Games/Game.exe')
        self.assertEqual(explain('example.com', settings, process='C:\\Games\\Game.exe')['route'], 'Напрямую')
        for process in ('Game.exe', 'C:/Other/Game.exe', 'C:/Games/Launcher.exe', 'C:/Games/game.exe'):
            with self.subTest(process=process):
                self.assertEqual(explain('example.com', settings, process=process)['route'], 'Через VPN')
        with self.assertRaises(ValueError):
            explain('example.com', settings, process='dota2.exe\ncs2.exe')

    def test_original_json_ignores_game_exceptions(self):
        _, config = build_config('{"outbounds":[{"tag":"direct","protocol":"freedom"}]}')
        normal = apply_routing(config, dict(DEFAULTS, preset='original'))
        self.assertEqual(apply_routing(config, dict(DEFAULTS, preset='original', game_mode=True)), normal)
        self.assertEqual(explain('example.com', dict(DEFAULTS, preset='original', game_mode=True),
                                 process='dota2.exe')['route'], 'По JSON')

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
