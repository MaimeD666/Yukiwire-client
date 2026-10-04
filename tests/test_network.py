import copy
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from contextlib import nullcontext
from yukiwire.network import ProxyLease, add_tun, new_tun, recover_journal, conflicts


class Journal:
    def __init__(self):
        self.value = None
        self.path = Mock(spec=Path)
        self.path.unlink.side_effect = lambda **kwargs: setattr(self, 'value', None)
    def write(self, value):
        self.value = copy.deepcopy(value)
    def read(self, default=None):
        return copy.deepcopy(self.value)


class Adapter:
    def __init__(self, state):
        self.state = copy.deepcopy(state)
        self.writes = []
    def read(self):
        return copy.deepcopy(self.state)
    def write(self, state):
        self.writes.append(copy.deepcopy(state))
        self.state = copy.deepcopy(state)


class ConflictDetectionTests(unittest.TestCase):
    def setUp(self):
        self.adapter = Adapter({'flags': 1, 'server': '', 'bypass': '', 'pac': ''})

    def test_closed_vpn_is_removed_on_next_scan(self):
        with patch('yukiwire.network.running_process_names', side_effect=[{'nekoray.exe'}, set()]), \
             patch('yukiwire.windows_snapshot.foreign_capture_present', return_value=False):
            self.assertTrue(conflicts(self.adapter)['other_vpn'])
            self.assertEqual(conflicts(self.adapter), {'other_proxy': False, 'other_vpn': False, 'check_failed': False})

    def test_closing_ui_does_not_hide_a_remaining_vpn_route_or_proxy(self):
        with patch('yukiwire.network.running_process_names', return_value=set()), \
             patch('yukiwire.windows_snapshot.foreign_capture_present', return_value=True):
            self.assertTrue(conflicts(self.adapter)['other_vpn'])
        self.adapter.state.update(flags=3, server='127.0.0.1:2080')
        with patch('yukiwire.network.running_process_names', return_value=set()), \
             patch('yukiwire.windows_snapshot.foreign_capture_present', return_value=False):
            self.assertTrue(conflicts(self.adapter)['other_proxy'])

    def test_incomplete_process_scan_cannot_certify_safe_capture(self):
        with patch('yukiwire.network.running_process_names', side_effect=OSError('denied')), \
             patch('yukiwire.windows_snapshot.foreign_capture_present', return_value=False):
            result = conflicts(self.adapter)
        self.assertTrue(result['check_failed'])
        self.assertTrue(result['other_vpn'])


class ProxyRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.original = {'flags': 9, 'server': 'old-disabled-proxy:3128', 'bypass': 'corporate', 'pac': 'https://corporate.invalid/proxy.pac'}
        self.adapter = Adapter(self.original)
        self.journal = Journal()
        self.lease = ProxyLease(self.journal, self.adapter)

    def test_prepare_has_no_network_side_effect(self):
        self.lease.prepare(100, 200)
        self.assertEqual(self.adapter.writes, [])
        self.assertEqual(self.journal.value['original'], self.original)

    def test_crash_before_apply_keeps_original(self):
        self.lease.prepare(100, 200)
        self.assertTrue(self.lease.recover()['restored'])
        self.assertEqual(self.adapter.writes, [])

    def test_crash_after_os_write_before_applied_record_restores(self):
        self.lease.prepare(100, 200)
        self.adapter.write(self.journal.value['desired'])
        self.assertEqual(self.journal.value['phase'], 'prepared')
        self.assertTrue(self.lease.recover()['restored'])
        self.assertEqual(self.adapter.read(), self.original)

    def test_new_nekoray_or_user_change_is_not_overwritten(self):
        self.lease.prepare(100, 200)
        self.lease.apply()
        changed = {'flags': 3, 'server': '127.0.0.1:2080', 'bypass': '<local>', 'pac': ''}
        self.adapter.write(changed)
        writes = len(self.adapter.writes)
        self.assertTrue(self.lease.recover()['conflict'])
        self.assertEqual(self.adapter.read(), changed)
        self.assertEqual(len(self.adapter.writes), writes)
        self.assertIsNotNone(self.journal.value)

    def test_settings_changed_during_prepare_abort_apply(self):
        self.lease.prepare(100, 200)
        self.adapter.state['flags'] = 1
        with self.assertRaises(ValueError):
            self.lease.apply()
        self.assertEqual(self.adapter.writes, [])

    def test_cannot_replace_active_other_proxy(self):
        self.adapter.state['flags'] = 3
        with self.assertRaises(ValueError):
            self.lease.prepare(100, 200)
        self.assertIsNone(self.journal.value)

    def test_no_mutation_when_journal_write_fails(self):
        self.journal.write = Mock(side_effect=OSError('disk full'))
        with self.assertRaises(OSError):
            self.lease.prepare(100, 200)
        self.assertEqual(self.adapter.writes, [])

    def test_original_pac_and_proxy_metadata_survive_roundtrip(self):
        self.lease.prepare(100, 200)
        self.lease.apply()
        self.lease.recover()
        self.assertEqual(self.adapter.read(), self.original)

    def recover_guarded(self, **kwargs):
        with patch('yukiwire.network.journal_lock', return_value=nullcontext()), \
             patch('yukiwire.network.WinInetProxy', return_value=self.adapter), \
             patch('yukiwire.network.unregister_recovery'):
            return recover_journal(self.journal, **kwargs)

    def test_old_watchdog_cannot_restore_a_new_lease(self):
        old = self.lease.prepare(100, 200)['lease_id']
        self.lease.prepare(101, 201)
        self.lease.apply()
        writes = len(self.adapter.writes)
        result = self.recover_guarded(expected_id=old)
        self.assertEqual(result['reason'], 'different_lease')
        self.assertEqual(len(self.adapter.writes), writes)
        self.assertIsNotNone(self.journal.value)

    def test_logon_recovery_preserves_active_owner(self):
        self.lease.prepare(100, 200)
        self.journal.value['owner_start'] = 12345
        self.lease.apply()
        with patch('yukiwire.network.process_identity', return_value=12345):
            result = self.recover_guarded(stale_only=True)
        self.assertEqual(result['reason'], 'active_owner')
        self.assertIsNotNone(self.journal.value)

    def test_pid_reuse_does_not_keep_a_dead_lease(self):
        self.lease.prepare(100, 200)
        self.journal.value['owner_start'] = 12345
        self.lease.apply()
        with patch('yukiwire.network.process_identity', return_value=67890):
            result = self.recover_guarded(stale_only=True)
        self.assertTrue(result['restored'])
        self.assertEqual(self.adapter.read(), self.original)

    def test_empty_start_does_not_touch_task_scheduler(self):
        with patch('yukiwire.network.journal_lock', return_value=nullcontext()), \
             patch('yukiwire.network.unregister_recovery') as remove:
            recover_journal(self.journal, stale_only=True)
        remove.assert_not_called()

    def test_normal_user_tun_recovery_keeps_journal_and_requests_elevated_helper(self):
        self.journal.value = {'version': 1, 'kind': 'tun', 'owner': 100, 'lease_id': 'test'}
        with patch('yukiwire.network.journal_lock', return_value=nullcontext()), \
             patch('yukiwire.network.process_identity', return_value=None), \
             patch('yukiwire.network.ctypes.windll.shell32.IsUserAnAdmin', return_value=0), \
             patch('yukiwire.network._recover_journal') as recover, \
             patch('yukiwire.network.unregister_recovery') as remove:
            result = recover_journal(self.journal, stale_only=True)
        self.assertTrue(result['requires_elevation'])
        recover.assert_not_called()
        remove.assert_not_called()
        self.assertIsNotNone(self.journal.value)

    def test_tun_changes_only_a_fresh_owned_interface(self):
        identity = new_tun()
        config = {'outbounds': [{'tag': 'server', 'protocol': 'vless'}], 'routing': {'rules': []}, 'inbounds': []}
        tun = add_tun(config, identity)['inbounds'][0]
        self.assertEqual(tun['settings']['name'], identity['adapter'])
        self.assertEqual(tun['settings']['autoSystemRoutingTable'], ['0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1'])
        self.assertNotIn('0.0.0.0/0', tun['settings']['autoSystemRoutingTable'])
        self.assertEqual(tun['settings']['autoOutboundsInterface'], 'auto')
