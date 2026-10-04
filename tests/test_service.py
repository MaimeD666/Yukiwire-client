import threading
import json
import unittest
from unittest.mock import Mock, patch
from yukiwire.backend import ApplicationService, Session
from yukiwire.network import tun_preflight


class ServiceTests(unittest.TestCase):
    def test_disabling_reconnect_does_not_disable_connection_health_checks(self):
        service = ApplicationService(Mock())
        service.analytics = None
        service.stop_requested.clear()
        service.session.core = Mock()
        service.session.core.process.poll.return_value = None
        service.session.settings['auto_reconnect'] = False
        service.failed_checks = 4
        service.session.telemetry = Mock()
        service.session.telemetry.sample.side_effect = ValueError('not available')
        service._probe = Mock()
        with patch.object(service.closing, 'wait', side_effect=[False, True]), \
             patch('yukiwire.backend.time.monotonic', return_value=100):
            service._monitor()
        service._probe.assert_called_once_with(manual=False)
        self.assertTrue(service.commands.empty())

    def test_duplicate_start_preserves_active_profile_and_counters(self):
        service = ApplicationService(Mock())
        service.stop_requested.clear()
        service.session.core = Mock()
        service.active_profile_id = 'current'
        service.last_profile = 'existing private configuration'
        service.session.completed_download = 123
        with self.assertRaises(ValueError):
            service._command({'action': 'start', 'profile_id': 'other'})
        self.assertEqual(service.active_profile_id, 'current')
        self.assertEqual(service.last_profile, 'existing private configuration')
        self.assertEqual(service.session.completed_download, 123)

    def test_environment_updates_while_idle_and_only_publishes_changes(self):
        events = []
        service = ApplicationService(lambda event, **values: events.append(dict(event=event, **values)))
        present = {'other_proxy': False, 'other_vpn': True}
        absent = {'other_proxy': False, 'other_vpn': False}
        with patch('yukiwire.backend.conflicts', side_effect=[present, present, absent, absent]):
            service._refresh_environment()
            service._refresh_environment()
            service._refresh_environment()
            service._command({'action': 'refresh_environment'})
        self.assertEqual(len(events), 3)
        self.assertEqual([e['environment']['other_vpn'] for e in events], [True, False, False])
        self.assertEqual([e['silent'] for e in events], [True, True, False])
        self.assertIsNone(service.session.core)
        self.assertTrue(service.commands.empty())

    def test_environment_failure_recovers_without_claiming_a_detected_vpn(self):
        events = []
        service = ApplicationService(lambda event, **values: events.append(values))
        with patch('yukiwire.backend.conflicts', side_effect=[OSError('unavailable'), {'other_proxy': False, 'other_vpn': False}]):
            service._refresh_environment()
            service._refresh_environment()
        self.assertTrue(events[0]['environment']['check_failed'])
        self.assertFalse(events[0]['environment']['other_vpn'])
        self.assertFalse(events[1]['environment'].get('check_failed', False))

    def test_environment_timer_runs_without_a_core_and_stops_on_close(self):
        service = ApplicationService(Mock())
        service.closing = Mock()
        service.closing.wait.side_effect = [False, True]
        service._refresh_environment = Mock()
        service._environment_monitor()
        service._refresh_environment.assert_called_once_with()
        self.assertEqual([call.args for call in service.closing.wait.call_args_list], [(5,), (5,)])

    def test_environment_scan_finishing_after_close_does_not_publish(self):
        emit = Mock()
        service = ApplicationService(emit)
        def scan():
            service.closing.set()
            return {'other_proxy': False, 'other_vpn': False}
        with patch('yukiwire.backend.conflicts', side_effect=scan):
            service._refresh_environment()
        emit.assert_not_called()

    def test_late_core_exit_cannot_stop_a_new_connection(self):
        emit = Mock()
        service = ApplicationService(emit)
        service.stop_requested.clear()
        service.session.generation = 4
        service.session.core = Mock()
        service.session.stop = Mock()
        service._command({'action': '_core_exited', 'generation': 3})
        service.session.stop.assert_not_called()
        emit.assert_not_called()

    def test_current_core_exit_stops_and_duplicate_notification_is_ignored(self):
        events = []
        service = ApplicationService(lambda event, **values: events.append(event))
        service.analytics = None
        service.stop_requested.clear()
        service.session.core = Mock()
        service.session.core.process.poll.return_value = 1
        generation = service.session.generation
        service._command({'action': '_core_exited', 'generation': generation})
        service._command({'action': '_core_exited', 'generation': generation})
        self.assertEqual(events.count('core_exited'), 1)
        self.assertEqual(events.count('stopped'), 1)
        self.assertIsNone(service.session.core)

    def test_browser_is_delegated_to_normal_user_host_after_connection_check(self):
        emit = Mock()
        service = ApplicationService(emit)
        with self.assertRaises(ValueError):
            service._command({'action': 'open_browser'})
        service.session.core = Mock()
        service.session.core.process.poll.return_value = None
        service.session.settings['capture'] = 'tun'
        service._command({'action': 'open_browser'})
        emit.assert_called_once_with('browser_requested')

    def test_health_probe_cannot_follow_a_direct_routing_exception(self):
        session = Session()
        session.core = Mock()
        session.core.process.poll.return_value = None
        with patch('yukiwire.backend.probe_https') as probe:
            session.probe()
        probe.assert_called_once_with(port=11812)

    def test_capture_is_applied_only_after_profile_probe_and_not_after_cancellation(self):
        from yukiwire.routing import DEFAULTS
        for cancel_during_probe in (False, True):
            with self.subTest(cancel=cancel_during_probe):
                session = Session()
                session.guard = Mock(kind='system')
                session.guard.recover.return_value = {'restored': True}
                core = Mock()
                core.process.poll.return_value = None
                core.close.side_effect = lambda: setattr(core.process.poll, 'return_value', 0)
                cancel = threading.Event()
                def checked(**kwargs):
                    session.guard.apply_proxy.assert_not_called()
                    if cancel_during_probe:
                        cancel.set()
                with patch('yukiwire.backend.conflicts', return_value={'other_proxy': False, 'other_vpn': False}), \
                     patch('yukiwire.backend.RuleSets') as rules, \
                     patch('yukiwire.backend.validate_config'), \
                     patch('yukiwire.backend.socket.socket') as socket, \
                     patch('yukiwire.backend.CoreProcess', return_value=core), \
                     patch('yukiwire.backend.probe_https', side_effect=checked) as probe:
                    rules.return_value.tags.return_value = {}
                    socket.return_value.__enter__.return_value.connect_ex.return_value = 0
                    profile = 'vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls'
                    try:
                        if cancel_during_probe:
                            with self.assertRaises(ValueError):
                                session.start(profile, dict(DEFAULTS, capture='system', preset='all'), cancel)
                            session.guard.apply_proxy.assert_not_called()
                        else:
                            session.start(profile, dict(DEFAULTS, capture='system', preset='all'), cancel)
                            session.guard.apply_proxy.assert_called_once()
                        probe.assert_called_once_with(port=11812)
                    finally:
                        session.stop()

    def test_unconfirmed_core_stop_retains_recovery_and_does_not_report_stopped(self):
        emit = Mock()
        service = ApplicationService(emit)
        core = service.session.core = Mock()
        core.process.poll.return_value = None
        core.close.side_effect = OSError('termination failed')
        service.session.guard = Mock(kind='system')
        with self.assertRaises(RuntimeError):
            service._command({'action': 'stop'})
        self.assertIs(service.session.core, core)
        service.session.guard.recover.assert_not_called()
        emit.assert_not_called()

    def test_incomplete_recovery_retains_guard_for_retry(self):
        session = Session()
        session.guard = Mock(kind='tun')
        session.guard.recover.return_value = {'restored': False, 'requires_elevation': True}
        with self.assertRaises(ValueError):
            session.stop()
        self.assertEqual(session.guard.kind, 'tun')

    def test_renderer_snapshot_preserves_core_and_never_returns_temporary_config(self):
        events = []
        profiles = Mock()
        profiles.public.return_value = {'profiles': [], 'selected': None}
        service = ApplicationService(lambda event, **values: events.append(dict(event=event, **values)), profiles=profiles)
        service.analytics = None
        service.session.core = Mock()
        service.session.core.process.poll.return_value = None
        service.session.core.process.pid = 123
        service.session.settings['preset'] = 'all'
        service.settings['preset'] = 'ru-direct'
        service.last_profile = 'vless://private-credential@private-host:443?security=tls'
        service.healthy = True
        service.session.generation = service.last_probe_generation = 5
        service.last_probe_result = {'http_status': 200, 'elapsed_ms': 15}
        with patch('yukiwire.backend.conflicts', return_value={}), patch('yukiwire.backend.RuleSets') as rules:
            rules.return_value.metadata.return_value = {}
            service._command({'action': 'get_state'})
        self.assertEqual(events[0]['settings']['preset'], 'all')
        self.assertEqual(events[1]['pid'], 123)
        self.assertEqual(events[1]['transient']['protocol'], 'vless')
        self.assertEqual(events[2]['event'], 'probe_result')
        serialized = json.dumps(events)
        self.assertNotIn('private-credential', serialized)
        self.assertNotIn('private-host', serialized)
        service.session.core.close.assert_not_called()

    def test_renderer_snapshot_rejects_health_and_site_results_from_old_generation(self):
        events = []
        profiles = Mock()
        profiles.public.return_value = {'profiles': [], 'selected': None}
        service = ApplicationService(lambda event, **values: events.append(event), profiles=profiles)
        service.analytics = None
        service.session.core = Mock()
        service.session.core.process.poll.return_value = None
        service.active_profile_id = 'saved'
        service.healthy = True
        service.session.generation = 6
        service.last_probe_generation = 5
        service.last_probe_result = {'http_status': 200, 'elapsed_ms': 15}
        service.site_results = {'generation': 5, 'results': [], 'exit': {}}
        with patch('yukiwire.backend.conflicts', return_value={}), patch('yukiwire.backend.RuleSets'):
            service._command({'action': 'get_state'})
        self.assertEqual(events, ['ready', 'started'])

    def test_old_site_matrix_cannot_publish_into_a_new_session(self):
        entered, release = threading.Event(), threading.Event()
        events = []
        service = ApplicationService(lambda event, **values: events.append(event))
        service.session.core = Mock()
        service.stop_requested.clear()
        def check():
            entered.set()
            release.wait(2)
            return {'results': [{'target': 'chatgpt.com', 'accessible': True, 'message': 'HTTP 200'}], 'exit': {}}
        with patch('yukiwire.backend.check_connection', check):
            service._command({'action': 'check_sites'})
            self.assertTrue(entered.wait(2))
            service.session.generation += 1
            release.set()
            self.assertTrue(service.sites_lock.acquire(timeout=2))
            service.sites_lock.release()
        self.assertNotIn('sites_result', events)
        self.assertIsNone(service.site_results)

    def test_old_probe_cannot_mark_disconnected_session_as_connected(self):
        entered, release = threading.Event(), threading.Event()
        events = []
        service = ApplicationService(lambda event, **values: events.append(event))
        service.session.core = Mock()
        service.stop_requested.clear()
        def probe():
            entered.set()
            release.wait(2)
            return {'http_status': 200, 'elapsed_ms': 1}
        service.session.probe = probe
        service._probe(False)
        self.assertTrue(entered.wait(2))
        service.session.generation += 1
        service.session.core = None
        service.stop_requested.set()
        release.set()
        self.assertTrue(service.probe_lock.acquire(timeout=2))
        service.probe_lock.release()
        self.assertNotIn('probe_result', events)
        self.assertFalse(service.healthy)

    def test_stale_restart_does_not_reconnect_a_new_session(self):
        service = ApplicationService(Mock())
        service.session.generation = 4
        service.session.start = Mock()
        service._command({'action': '_restart', 'generation': 3})
        service.session.start.assert_not_called()

    def test_stop_cancels_pending_connection_and_terminates_only_owned_core(self):
        service = ApplicationService(Mock())
        service.session.core = Mock()
        service.session.core.process.poll.return_value = None
        service.stop_requested.clear()
        service.submit({'action': 'stop'})
        self.assertTrue(service.stop_requested.is_set())
        service.session.core.process.terminate.assert_called_once()

    def test_tun_subnet_overlap_aborts_without_mutation(self):
        with patch('yukiwire.network.inspect_tun', return_value={'addresses': ['172.29.0.1/16']}):
            with self.assertRaises(ValueError):
                tun_preflight()
        with patch('yukiwire.network.inspect_tun', return_value={'addresses': ['192.168.1.2/24', 'fe80::1/64']}):
            tun_preflight()

    def test_local_mode_does_not_monitor_or_interfere_with_nekoray(self):
        service = ApplicationService(Mock())
        service.stop_requested.clear()
        with patch('yukiwire.backend.conflicts') as check:
            service._check_capture(1)
        check.assert_not_called()
        self.assertTrue(service.commands.empty())

    def test_another_vpn_stops_system_capture_instead_of_taking_it_back(self):
        service = ApplicationService(Mock())
        service.stop_requested.clear()
        service.session.settings['capture'] = 'system'
        service.session.guard.journal = Mock()
        service.session.guard.journal.read.return_value = {'desired': {'flags': 3}, 'lease_id': 'test'}
        service.session.guard.lease_id = 'test'
        with patch('yukiwire.backend.conflicts', return_value={'other_proxy': False, 'other_vpn': True}), \
             patch('yukiwire.backend.WinInetProxy') as proxy:
            proxy.return_value.read.return_value = {'flags': 3}
            service._check_capture(5)
        self.assertEqual(service.commands.get_nowait(), {'action': '_capture_conflict', 'generation': 5})

    def test_missing_tun_route_schedules_guarded_reconnect(self):
        service = ApplicationService(Mock())
        service.stop_requested.clear()
        service.session.settings['capture'] = 'tun'
        service.session.guard.journal = Mock()
        service.session.guard.journal.read.return_value = {'lease_id': 'test'}
        service.session.guard.lease_id = 'test'
        with patch('yukiwire.backend.conflicts', return_value={'other_proxy': False, 'other_vpn': False}), \
             patch('yukiwire.backend.tun_ready', return_value=False):
            service._check_capture(5)
        self.assertTrue(service.restarting)
        self.assertEqual(service.commands.get_nowait(), {'action': '_restart', 'generation': 5})

    def test_stale_conflict_cannot_disconnect_a_new_session(self):
        service = ApplicationService(Mock())
        service.stop_requested.clear()
        service.session.generation = 6
        service.session.stop = Mock()
        service._command({'action': '_capture_conflict', 'generation': 5})
        service.session.stop.assert_not_called()
        self.assertFalse(service.stop_requested.is_set())

    def test_stop_acknowledges_closed_core_even_if_network_restore_conflicts(self):
        events = []
        service = ApplicationService(lambda event, **values: events.append(event))
        service.session.stop = Mock(side_effect=ValueError('foreign proxy retained'))
        with self.assertRaises(ValueError):
            service._command({'action': 'stop'})
        self.assertIn('stopped', events)
        self.assertFalse(service.healthy)
