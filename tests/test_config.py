import json
import base64
import unittest
from yukiwire.config import build_config


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

    def test_incompatible_json(self):
        with self.assertRaises(ValueError):
            build_config('{"proxies": []}')

    def test_system_interface_outbound_is_rejected(self):
        with self.assertRaises(ValueError):
            build_config('{"outbounds": [{"protocol": "wireguard", "settings": {"kernelMode": true}}]}')


if __name__ == '__main__':
    unittest.main()
