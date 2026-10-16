import threading
import unittest
from unittest.mock import Mock, patch

from yukiwire.broker import ElevatedCore, RemoteProcess
from yukiwire.network import tun_clean


class BrokerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.result = dict(pid=123, serial=7, core_start=456, adapter='Yukiwire-0123456789ab', description='Yukiwire 0123456789ab')
        self.broker = Mock(closed=threading.Event(), exits={})
        self.broker.request.side_effect = lambda action, **fields: self.result if action == 'prepare' else True

    def test_helper_identity_is_journaled_before_core_receives_configuration(self):
        identity = {}
        def arm(pid):
            self.assertEqual(pid, 123)
            self.assertEqual(identity['adapter'], self.result['adapter'])
            self.assertTrue(identity['protected_helper'])
            self.assertEqual([call.args[0] for call in self.broker.request.call_args_list], ['prepare'])
        core = ElevatedCore(self.broker, {}, identity, arm)
        self.assertEqual([call.args[0] for call in self.broker.request.call_args_list], ['prepare', 'start'])
        core.close()
        self.broker.request.assert_called_with('stop', serial=7)

    def test_cancelled_preparation_never_starts_core(self):
        with self.assertRaises(ValueError):
            ElevatedCore(self.broker, {}, {}, Mock(side_effect=ValueError('cancelled')))
        self.assertEqual([call.args[0] for call in self.broker.request.call_args_list], ['prepare', 'stop'])

    def test_exit_notifications_are_bound_to_core_serial(self):
        process = RemoteProcess(self.broker, self.result)
        self.broker.exits[6] = {'code': 1}
        with patch('yukiwire.network.process_identity', return_value=456):
            self.assertIsNone(process.poll())
        self.broker.exits[7] = {'code': 2}
        self.assertEqual(process.poll(), 2)

    def test_failed_cleanup_does_not_hide_a_terminated_core_on_live_ipc(self):
        process = RemoteProcess(self.broker, self.result)
        self.assertFalse(self.broker.closed.is_set())
        with patch('yukiwire.network.process_identity', return_value=None):
            self.assertEqual(process.poll(), 1)

    def test_pipe_death_does_not_claim_live_core_is_stopped(self):
        process = RemoteProcess(self.broker, self.result)
        self.broker.closed.set()
        with patch('yukiwire.network.process_identity', return_value=456):
            self.assertIsNone(process.poll())
        with patch('yukiwire.network.process_identity', return_value=None):
            self.assertEqual(process.poll(), 1)

    def test_cleanup_confirmation_checks_addresses_dns_routes_and_identity(self):
        identity = dict(self.result, core=123)
        adapter = {'name': identity['adapter'], 'description': identity['description'] + ' Tunnel',
                   'index': 42, 'index6': 42, 'up': False, 'addresses': [], 'dns': []}
        with patch('yukiwire.network.process_identity', return_value=None), \
             patch('yukiwire.windows_snapshot.adapters', return_value=[adapter]), \
             patch('yukiwire.windows_snapshot.routes', return_value=[]) as routes:
            self.assertTrue(tun_clean(identity))
            for key, bad in [('up', True), ('addresses', ['172.29.250.1/30']), ('dns', ['172.29.250.2'])]:
                old = adapter[key]; adapter[key] = bad
                self.assertFalse(tun_clean(identity)); adapter[key] = old
            routes.return_value = [{'index': 42, 'prefix': '8000::/1'}]
            self.assertFalse(tun_clean(identity))
            routes.return_value = []
            adapter['description'] = 'another adapter'
            with self.assertRaises(ValueError): tun_clean(identity)


if __name__ == '__main__':
    unittest.main()
