"""Exercise the exact native privilege-boundary policy without elevation/TUN."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from yukiwire.config import build_config
from yukiwire.endpoints import allocate_endpoints, configure_local
from yukiwire.health import diagnostic_config
from yukiwire.network import add_tun
from yukiwire.routing import apply_routing, DEFAULTS
from yukiwire.telemetry import enable_metrics

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'nt', 'Windows native boundary')
class NetworkPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='yukiwire-policy-')
        cls.executable = Path(cls.temporary.name) / 'Policy.exe'
        framework = Path(os.environ['WINDIR']) / 'Microsoft.NET/Framework64/v4.0.30319'
        subprocess.run([str(framework / 'csc.exe'), '/nologo', '/target:exe', '/platform:x64',
                        '/out:' + str(cls.executable), '/reference:' + str(framework / 'System.Web.Extensions.dll'),
                        str(ROOT / 'native/NetworkPolicy.cs'), str(ROOT / 'tests/NetworkPolicyHarness.cs')], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def configuration(self, combined=True):
        _, config = build_config('vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&type=xhttp&path=%2Ftest')
        settings = dict(DEFAULTS, capture='tun', preset='all', tun_system_proxy=combined)
        endpoints = allocate_endpoints()
        config = apply_routing(config, settings)
        config = configure_local(config, endpoints, settings)
        config = enable_metrics(config, endpoints['metrics'])
        config = diagnostic_config(config, endpoints['probe'])
        return add_tun(config, {'adapter': 'Yukiwire-aaaaaaaaaaaa', 'description': 'Yukiwire aaaaaaaaaaaa'}, settings, ['192.0.2.53'])

    def validate(self, config):
        result = subprocess.run([str(self.executable)], input=json.dumps(config).encode(), capture_output=True, timeout=10)
        return result.returncode, json.loads(result.stdout) if result.returncode == 0 else None

    def test_managed_tun_and_combined_keep_auth_routing_and_use_helper_identity(self):
        for combined in (False, True):
            with self.subTest(combined=combined):
                original = self.configuration(combined)
                code, result = self.validate(original)
                self.assertEqual(code, 0)
                tun = next(x for x in result['inbounds'] if x['protocol'] == 'tun')
                self.assertEqual(tun['settings']['name'], 'Yukiwire-0123456789ab')
                self.assertEqual(result['routing'], original['routing'])
                self.assertEqual(result['outbounds'], original['outbounds'])
                self.assertEqual(len(result['inbounds']), 5 if combined else 3)

    def test_privileged_config_cannot_load_code_read_keys_or_write_files(self):
        config = self.configuration()
        cases = []
        for field in ('env', 'api', 'geodata', 'reverse', 'observatory'):
            candidate = copy.deepcopy(config); candidate[field] = {}; cases.append(candidate)
        for field in ('script', 'Script', 'SCRIPT'):
            candidate = copy.deepcopy(config); candidate['dns'][field] = 'C:/untrusted.lua'; cases.append(candidate)
        for field in ('keyFile', 'certificateFile', 'masterKeyLog', 'masterKeyLogFile', 'certificates'):
            candidate = copy.deepcopy(config); candidate['outbounds'][0]['streamSettings']['tlsSettings'][field] = 'C:/secret'; cases.append(candidate)
        candidate = copy.deepcopy(config); candidate['routing']['rules'].append({'domain': ['ext:C:/secret:ru'], 'outboundTag': 'proxy'}); cases.append(candidate)
        candidate = copy.deepcopy(config); candidate['outbounds'][0]['streamSettings']['tlsSettings']['allowInsecure'] = True; cases.append(candidate)
        for candidate in cases:
            with self.subTest(index=cases.index(candidate)):
                self.assertNotEqual(self.validate(candidate)[0], 0)
        config['log'] = {'access': 'C:/sensitive', 'error': 'C:/sensitive'}
        self.assertEqual(self.validate(config)[1]['log'], {'loglevel': 'warning'})

    def test_new_transports_cannot_enable_kernel_wireguard_or_hysteria_file_serving(self):
        config = self.configuration()
        _, hysteria = build_config('hy2://fixture@192.0.2.1?sni=server.example.com&obfs=salamander&obfs-password=fixture')
        config['outbounds'][0] = hysteria['outbounds'][0]
        self.assertEqual(self.validate(config)[0], 0)
        config['outbounds'][0]['streamSettings']['hysteriaSettings']['masquerade'] = {'type': 'file', 'dir': 'C:/private'}
        self.assertNotEqual(self.validate(config)[0], 0)
        config['outbounds'][0] = {'protocol': 'wireguard', 'settings': {'noKernelTun': True}}
        self.assertEqual(self.validate(config)[0], 0)
        config['outbounds'][0]['settings']['noKernelTun'] = False
        self.assertNotEqual(self.validate(config)[0], 0)

    def test_untrusted_listeners_and_weak_credentials_are_rejected(self):
        for alteration in ('listen', 'port', 'password', 'extra'):
            config = self.configuration()
            if alteration == 'listen': config['inbounds'][0]['listen'] = '0.0.0.0'
            elif alteration == 'port': config['inbounds'][0]['port'] = 53
            elif alteration == 'password': next(x for x in config['inbounds'] if x['tag'] == 'yukiwire-check')['settings']['accounts'][0]['pass'] = 'weak'
            else: config['inbounds'].append({'tag': 'evil', 'protocol': 'dokodemo-door'})
            with self.subTest(alteration=alteration): self.assertNotEqual(self.validate(config)[0], 0)


if __name__ == '__main__':
    unittest.main()
