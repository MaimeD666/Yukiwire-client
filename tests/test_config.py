import json
import base64
import unittest
from yukiwire.config import build_config, profile_warnings


class ConfigTests(unittest.TestCase):
    def test_vmess_preserves_websocket_tls_and_identity(self):
        profile = {'v': '2', 'ps': 'VMess demo', 'add': '192.0.2.1', 'port': '443', 'id': '00000000-0000-4000-8000-000000000001',
                   'aid': '0', 'net': 'ws', 'type': 'none', 'tls': 'tls', 'host': 'cdn.example', 'path': '/socket', 'sni': 'tls.example'}
        name, config = build_config('vmess://' + base64.b64encode(json.dumps(profile).encode()).decode())
        outbound = config['outbounds'][0]
        self.assertEqual(name, 'VMess demo')
        self.assertEqual(outbound['protocol'], 'vmess')
        self.assertEqual(outbound['streamSettings']['wsSettings']['headers']['Host'], 'cdn.example')
        self.assertEqual(outbound['streamSettings']['tlsSettings']['serverName'], 'tls.example')
        self.assertEqual(outbound['settings']['vnext'][0]['users'][0]['alterId'], 0)

    def test_trojan_percent_encoded_password_and_transport(self):
        _, config = build_config('trojan://p%40ss%3Aword@192.0.2.1:443?type=ws&path=%2Fsocket&sni=tls.example')
        outbound = config['outbounds'][0]
        self.assertEqual(outbound['settings']['servers'][0]['password'], 'p@ss:word')
        self.assertEqual(outbound['streamSettings']['security'], 'tls')
        self.assertEqual(outbound['streamSettings']['wsSettings']['path'], '/socket')

    def test_shadowsocks_both_base64_link_forms(self):
        for profile in ('ss://' + base64.urlsafe_b64encode(b'aes-256-gcm:p@ss:word').decode().rstrip('=') + '@192.0.2.1:8388#demo',
                        'ss://' + base64.b64encode(b'aes-256-gcm:p@ss:word@192.0.2.1:8388').decode() + '#demo'):
            name, config = build_config(profile)
            self.assertEqual(name, 'demo')
            self.assertEqual(config['outbounds'][0]['settings']['servers'][0]['password'], 'p@ss:word')

    def test_xhttp_link(self):
        name, config = build_config('vless://00000000-0000-4000-8000-000000000001@192.0.2.1:8443?encryption=none&security=tls&sni=192.0.2.1&fp=firefox&alpn=h2&type=xhttp&path=%2Fapi%2Fv2%2Fsync%2F&mode=stream-one#test')
        stream = config['outbounds'][0]['streamSettings']
        self.assertEqual(stream['xhttpSettings'], {'path': '/api/v2/sync/', 'mode': 'stream-one'})
        self.assertEqual(stream['tlsSettings']['alpn'], ['h2'])
        self.assertFalse(stream['tlsSettings']['allowInsecure'])
        self.assertTrue(all(i['listen'] == '127.0.0.1' for i in config['inbounds']))

    def test_json_cannot_open_external_listener_or_log_credentials(self):
        _, config = build_config(json.dumps({'inbounds': [{'listen': '0.0.0.0'}], 'log': {'access': 'secret.txt'}, 'api': {}, 'outbounds': [{'protocol': 'freedom'}]}))
        self.assertNotIn('api', config)
        self.assertNotIn('access', config['log'])
        self.assertEqual(len(config['inbounds']), 2)

    def test_unknown_parameter_not_silently_lost(self):
        with self.assertRaises(ValueError):
            build_config('vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?extra=secret')

    def test_invalid_identity(self):
        with self.assertRaises(ValueError):
            build_config('vless://invalid@192.0.2.1:443')

    def test_panel_defaults_and_unknown_metadata_are_compatible(self):
        profile = 'vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls&headerType=none&private-metadata=do-not-log'
        _, config = build_config(profile)
        self.assertFalse(config['outbounds'][0]['streamSettings']['tlsSettings']['allowInsecure'])
        warning = ' '.join(profile_warnings(profile))
        self.assertTrue(warning)
        self.assertNotIn('private-metadata', warning)
        self.assertNotIn('do-not-log', warning)

    def test_trojan_peer_alias_and_false_insecure_option(self):
        _, config = build_config('trojan://password@192.0.2.1:443?peer=tls.example&allowInsecure=0')
        tls = config['outbounds'][0]['streamSettings']['tlsSettings']
        self.assertEqual(tls['serverName'], 'tls.example')
        self.assertFalse(tls['allowInsecure'])

    def test_link_cannot_silently_disable_tls_verification(self):
        with self.assertRaisesRegex(ValueError, 'TLS'):
            build_config('trojan://password@192.0.2.1:443?allowInsecure=1')

    def test_httpupgrade_preserves_host_and_path(self):
        _, config = build_config('trojan://password@192.0.2.1:443?type=httpupgrade&host=cdn.example&path=%2Fupgrade')
        stream = config['outbounds'][0]['streamSettings']
        self.assertEqual(stream['httpupgradeSettings'], {'host': 'cdn.example', 'path': '/upgrade'})

    def test_reality_requires_key_and_preserves_post_quantum_verification(self):
        profile = 'vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=reality'
        with self.assertRaisesRegex(ValueError, 'pbk'):
            build_config(profile)
        _, config = build_config(profile + '&pbk=test-key&pqv=test-verification')
        self.assertEqual(config['outbounds'][0]['streamSettings']['realitySettings']['mldsa65Verify'], 'test-verification')

    def test_ambiguous_security_parameters_are_rejected(self):
        with self.assertRaises(ValueError):
            build_config('trojan://password@192.0.2.1:443?security=tls&security=none')

    def test_incompatible_json(self):
        with self.assertRaises(ValueError):
            build_config('{"proxies": []}')

    def test_hysteria2_preserves_auth_ipv6_sni_and_obfuscation(self):
        name, config = build_config('hy2://user%3Apass@[2001:db8::1]:8443?sni=server.example.com&obfs=salamander&obfs-password=fixture#Hysteria')
        outbound = config['outbounds'][0]
        self.assertEqual(name, 'Hysteria')
        self.assertEqual(outbound['settings'], {'version': 2, 'address': '2001:db8::1', 'port': 8443})
        self.assertEqual(outbound['streamSettings']['hysteriaSettings']['auth'], 'user:pass')
        self.assertEqual(outbound['streamSettings']['finalmask']['udp'][0]['settings']['password'], 'fixture')
        for suffix in ('?insecure=1', '?pinSHA256=bad', '?obfs=unknown', '?obfs=salamander'):
            with self.assertRaises(ValueError): build_config('hy2://fixture@192.0.2.1' + suffix)

    def test_wireguard_is_forced_to_userspace_and_h2_is_explicitly_rejected(self):
        _, config = build_config('{"outbounds":[{"protocol":"wireguard","settings":{}}]}')
        self.assertTrue(config['outbounds'][0]['settings']['noKernelTun'])
        with self.assertRaises(ValueError):
            build_config('{"outbounds":[{"protocol":"wireguard","settings":{"noKernelTun":false}}]}')
        with self.assertRaisesRegex(ValueError, 'H2'):
            build_config('trojan://fixture@192.0.2.1:443?type=h2')

    def test_system_interface_outbound_is_rejected(self):
        with self.assertRaises(ValueError):
            build_config('{"outbounds": [{"protocol": "wireguard", "settings": {"kernelMode": true}}]}')


if __name__ == '__main__':
    unittest.main()
