import unittest
import ssl
from unittest.mock import patch

from yukiwire.health import probe_https, check_sites, trace_country, diagnostic_config


class HealthTests(unittest.TestCase):
    def test_tun_probe_uses_os_route_without_an_explicit_proxy(self):
        with patch('yukiwire.health.http.client.HTTPSConnection') as factory:
            factory.return_value.getresponse.return_value.status = 200
            result = probe_https(port=None, host='www.youtube.com')
            self.assertEqual(factory.call_args.args, ('www.youtube.com', 443))
            factory.return_value.set_tunnel.assert_not_called()
            self.assertEqual(result['path'], 'tun')
            self.assertIsNone(result['proxy_port'])
            factory.return_value.close.assert_called_once()

    def test_tun_failure_is_not_hidden_by_working_vpn_proxy(self):
        error = ssl.SSLError('TLS failure')
        error.reason = 'DECRYPTION_FAILED_OR_BAD_RECORD_MAC'
        with patch('yukiwire.health.SITES', ('www.youtube.com',)), \
             patch('yukiwire.health.probe_https', side_effect=[error, {'http_status': 200}]) as probe:
            result = check_sites(capture='tun')[0]
        self.assertFalse(result['accessible'])
        self.assertFalse(result['transport_ok'])
        self.assertTrue(result['vpn_transport_ok'])
        self.assertEqual(result['tls_error'], 'bad_record_mac')
        self.assertEqual(result['vpn_http_status'], 200)
        self.assertEqual([call.kwargs['port'] for call in probe.call_args_list], [None, 11812])

    def test_tun_and_vpn_failure_does_not_claim_local_conflict(self):
        with patch('yukiwire.health.SITES', ('www.youtube.com',)), \
             patch('yukiwire.health.probe_https', side_effect=TimeoutError):
            result = check_sites(capture='tun')[0]
        self.assertFalse(result['vpn_transport_ok'])
        self.assertNotIn('zapret', result['message'])

    def test_tun_http_denial_is_not_retried_or_called_a_tls_failure(self):
        with patch('yukiwire.health.SITES', ('www.youtube.com',)), \
             patch('yukiwire.health.probe_https', return_value={'target': 'www.youtube.com', 'http_status': 403}) as probe:
            result = check_sites(capture='tun')[0]
        self.assertTrue(result['transport_ok'])
        self.assertFalse(result['accessible'])
        probe.assert_called_once_with(port=None, host='www.youtube.com', timeout=10)
        self.assertNotIn('vpn_transport_ok', result)

    def test_system_and_local_checks_still_use_the_routed_proxy(self):
        for capture in ('local', 'system'):
            with self.subTest(capture=capture), patch('yukiwire.health.SITES', ('www.youtube.com',)), \
                 patch('yukiwire.health.probe_https', side_effect=TimeoutError) as probe:
                result = check_sites(port=12345, capture=capture)[0]
                probe.assert_called_once_with(port=12345, host='www.youtube.com', timeout=10)
                self.assertNotIn('vpn_transport_ok', result)

    def test_exit_country_uses_client_location_not_datacenter_and_discards_ip(self):
        self.assertEqual(trace_country(b'ip=192.0.2.42\nloc=DE\ncolo=SJC\n'), 'DE')
        with self.assertRaises(ValueError):
            trace_country(b'<html>Country blocked</html>')

    def test_profile_exit_probe_does_not_inherit_selected_sites_fallback(self):
        config = {'inbounds': [], 'outbounds': [{'tag': 'main', 'protocol': 'vless'}, {'tag': 'direct', 'protocol': 'freedom'}],
                  'routing': {'rules': [{'type': 'field', 'network': 'tcp,udp', 'outboundTag': 'direct'}]}}
        result = diagnostic_config(config)
        self.assertEqual(result['routing']['rules'][0]['inboundTag'], ['yukiwire-check'])
        self.assertEqual(result['routing']['rules'][0]['outboundTag'], 'main')
        self.assertEqual(result['routing']['rules'][1]['outboundTag'], 'direct')
        self.assertEqual(result['inbounds'][0]['listen'], '127.0.0.1')

    def test_site_denial_is_not_presented_as_successful_access(self):
        with patch('yukiwire.health.SITES', ('chatgpt.com',)), patch('yukiwire.health.probe_https', return_value={'target': 'chatgpt.com', 'http_status': 403, 'tls_verified': True}):
            result = check_sites()[0]
            self.assertTrue(result['transport_ok'])
            self.assertFalse(result['accessible'])
            self.assertIn('403', result['message'])

    def test_site_connection_failure_is_separate_from_http_denial(self):
        with patch('yukiwire.health.SITES', ('chatgpt.com',)), patch('yukiwire.health.probe_https', side_effect=ConnectionResetError):
            result = check_sites()[0]
            self.assertFalse(result['transport_ok'])
            self.assertFalse(result['accessible'])
            self.assertNotIn('http_status', result)
    def test_connect_tunnel_preserves_origin_host(self):
        with patch('yukiwire.health.http.client.HTTPSConnection') as factory:
            connection = factory.return_value
            connection.getresponse.return_value.status = 200
            result = probe_https(port=11809, host='example.com')
            self.assertEqual(factory.call_args.args, ('127.0.0.1', 11809))
            connection.set_tunnel.assert_called_once_with('example.com', 443, headers={})
            args, kwargs = connection.request.call_args
            self.assertEqual(args, ('GET', '/'))
            self.assertEqual(kwargs['headers']['Host'], 'example.com')
            self.assertEqual(result['http_status'], 200)
            connection.close.assert_called_once()

    def test_http_error_is_distinguished_from_tunnel_failure(self):
        with patch('yukiwire.health.http.client.HTTPSConnection') as factory:
            factory.return_value.getresponse.return_value.status = 403
            result = probe_https()
            self.assertTrue(result['tls_verified'])
            self.assertEqual(result['http_status'], 403)

    def test_socket_closed_on_failed_tls_or_request(self):
        with patch('yukiwire.health.http.client.HTTPSConnection') as factory:
            factory.return_value.request.side_effect = ConnectionResetError()
            with self.assertRaises(ConnectionResetError):
                probe_https()
            factory.return_value.close.assert_called_once()
