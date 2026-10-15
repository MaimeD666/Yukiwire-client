"""Saving live settings must never confuse desired state with the running session."""
import unittest
from unittest.mock import Mock, patch

from yukiwire.backend import ApplicationService, NetworkConflict
from yukiwire.routing import DEFAULTS, connection_settings, normalize_settings

PROFILE = 'vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls'


class SettingsApplyTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.service = s = ApplicationService(lambda event, **values: self.events.append(dict(event=event, **values)), settings_file=Mock())
        s.analytics = None
        s.settings = dict(DEFAULTS, preset='all')
        s.session.settings = dict(s.settings)
        s.session.core = Mock()
        s.session.core.process.poll.return_value = None
        s.stop_requested.clear()
        s.last_profile = PROFILE
        s.active_profile_id = 'saved-profile'
        s._probe = Mock()
        def stop():
            s.session.core = None
            s.session.generation += 1
        def start(profile, settings, cancel):
            s.session.settings = dict(settings)
            s.session.core = Mock()
            s.session.core.process.poll.return_value = None
            s.session.generation += 1
            return dict(pid=123, capture=settings['capture'])
        s.session.stop = Mock(side_effect=stop)
        s.session.start = Mock(side_effect=start)
        self.start = start
        self.patchers = [patch('yukiwire.backend.validate_config'),
                         patch('yukiwire.backend.RuleSets'), patch('yukiwire.backend.check_connection', return_value={'results': [], 'exit': {}})]
        self.validate, rules, _ = [p.start() for p in self.patchers]
        rules.return_value.tags.return_value = {}
        for p in self.patchers:
            self.addCleanup(p.stop)

    def save(self, **changes):
        self.service._command(dict(action='save_settings', settings=dict(self.service.settings, **changes)))

    def test_opt_in_defaults_off_and_only_accepts_boolean(self):
        self.assertFalse(normalize_settings({})['reconnect_on_change'])
        with self.assertRaises(ValueError):
            normalize_settings({'reconnect_on_change': 'true'})

    def test_save_while_active_with_opt_out_preserves_running_routes(self):
        self.save(proxy='example.com')
        self.service.session.stop.assert_not_called()
        self.assertEqual(self.service.session.settings['proxy'], '')
        self.assertTrue(self.events[0]['settings_pending'])
        self.assertEqual(self.service.settings['proxy'], 'example.com')
        self.service.settings_file.write.assert_called_once()

    def test_recovery_preference_applies_without_restarting(self):
        self.save(auto_reconnect=False, reconnect_on_change=True)
        self.assertFalse(self.service.session.settings['auto_reconnect'])
        self.service.session.stop.assert_not_called()
        self.assertFalse(self.events[0]['settings_pending'])

    def test_enabling_auto_apply_also_applies_previously_pending_routes(self):
        self.save(proxy='example.com')
        self.save(reconnect_on_change=True)
        self.service.session.stop.assert_called_once()
        self.service.session.start.assert_called_once()
        self.assertEqual(self.service.session.settings['proxy'], 'example.com')
        self.assertEqual(self.service.active_profile_id, 'saved-profile')
        started = next(e for e in self.events if e['event'] == 'started')
        self.assertFalse(started['settings_pending'])
        self.assertEqual(started['active_settings']['proxy'], 'example.com')
        self.assertFalse(self.service.restarting)

    def test_invalid_candidate_keeps_connection_and_saved_settings(self):
        self.validate.side_effect = ValueError('invalid core config')
        with self.assertRaises(ValueError):
            self.save(reconnect_on_change=True, proxy='example.com')
        self.service.session.stop.assert_not_called()
        self.service.settings_file.write.assert_not_called()
        self.assertEqual(self.service.settings['proxy'], '')

    def test_storage_failure_does_not_interrupt_vpn(self):
        self.service.settings_file.write.side_effect = OSError('disk full')
        with self.assertRaises(OSError):
            self.save(reconnect_on_change=True, proxy='example.com')
        self.service.session.stop.assert_not_called()
        self.assertEqual(self.service.settings['proxy'], '')

    def test_failed_start_restores_previous_connection_once_and_retains_pending(self):
        def fail_new(profile, settings, cancel):
            if settings['proxy']:
                raise ValueError('startup failed')
            return self.start(profile, settings, cancel)
        self.service.session.start.side_effect = fail_new
        with self.assertRaisesRegex(ValueError, 'предыдущее'):
            self.save(reconnect_on_change=True, proxy='example.com')
        self.assertEqual(self.service.session.start.call_count, 2)
        self.assertEqual(self.service.session.settings['proxy'], '')
        self.assertEqual(self.service.settings['proxy'], 'example.com')
        started = next(e for e in self.events if e['event'] == 'started')
        self.assertTrue(started['settings_pending'])
        self.assertNotIn('stopped', [e['event'] for e in self.events])

    def test_network_conflict_does_not_attempt_to_retake_capture(self):
        self.service.session.start.side_effect = NetworkConflict('other VPN')
        with self.assertRaises(NetworkConflict):
            self.save(reconnect_on_change=True, proxy='example.com')
        self.service.session.start.assert_called_once()
        self.assertIn('stopped', [e['event'] for e in self.events])
        self.assertFalse(self.service.restarting)

    def test_failed_network_cleanup_never_starts_another_core(self):
        self.service.session.stop.side_effect = ValueError('cleanup incomplete')
        with self.assertRaises(ValueError):
            self.save(reconnect_on_change=True, proxy='example.com')
        self.service.session.start.assert_not_called()
        self.assertIsNotNone(self.service.session.core)

    def test_failed_start_with_unrestored_network_does_not_attempt_rollback(self):
        def failed(profile, settings, cancel):
            self.service.session.guard.kind = 'tun'
            raise ValueError('network cleanup incomplete')
        self.service.session.start.side_effect = failed
        with self.assertRaises(ValueError):
            self.save(reconnect_on_change=True, proxy='example.com')
        self.service.session.start.assert_called_once()
        self.assertEqual(self.service.session.guard.kind, 'tun')

    def test_stop_during_validation_wins_over_auto_apply(self):
        self.validate.side_effect = lambda config: self.service.submit({'action': 'stop'})
        self.save(reconnect_on_change=True, proxy='example.com')
        self.service.session.start.assert_not_called()
        self.service.session.core.process.terminate.assert_called_once()

    def test_stop_during_start_closes_new_core_without_restart_or_rollback(self):
        def cancel(profile, settings, event):
            result = self.start(profile, settings, event)
            event.set()
            return result
        self.service.session.start.side_effect = cancel
        self.save(reconnect_on_change=True, proxy='example.com')
        self.service.session.start.assert_called_once()
        self.assertIsNone(self.service.session.core)
        self.assertNotIn('started', [e['event'] for e in self.events])

    def test_local_to_tun_restarts_session_without_elevating_python(self):
        with patch('yukiwire.backend.ctypes.windll.shell32.IsUserAnAdmin', return_value=0):
            self.save(reconnect_on_change=True, capture='tun')
        self.service.session.stop.assert_called_once()
        self.service.session.start.assert_called_once()
        self.assertEqual(self.service.session.start.call_args.args[1]['capture'], 'tun')
        self.assertNotIn('settings_elevation_required', [e['event'] for e in self.events])
        self.assertIn('started', [e['event'] for e in self.events])

    def test_dormant_options_do_not_reconnect_other_presets_or_capture_modes(self):
        self.save(reconnect_on_change=True, ru_ip=True, tun_system_proxy=True, game_processes='cs2.exe')
        self.service.session.stop.assert_not_called()
        self.assertEqual(connection_settings(self.service.settings), connection_settings(self.service.session.settings))

    def test_late_health_restart_is_ignored_after_settings_restart(self):
        generation = self.service.session.generation
        self.save(reconnect_on_change=True, proxy='example.com')
        self.service._command(dict(action='_restart', generation=generation))
        self.service.session.start.assert_called_once()


if __name__ == '__main__':
    unittest.main()
