import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from yukiwire.backend import ApplicationService, validate_config
from yukiwire.broker import ElevatedCore
from yukiwire.config import build_config
from yukiwire.killswitch import KillSwitch, configure, enabled
from yukiwire.routing import DEFAULTS, apply_routing, connection_settings
from yukiwire.storage import SecureFile
from yukiwire.paths import CORE


class KillSwitchTests(unittest.TestCase):
    def test_arm_journals_before_filter_commit_and_failed_arm_keeps_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            protection = KillSwitch(SecureFile(Path(directory) / 'protection', cipher=lambda data, decrypt=False: data))
            broker = Mock(identity='a' * 32, closed=threading.Event())
            def arm(action, **fields):
                self.assertEqual(action, 'arm')
                self.assertEqual(protection.file.read()['helper_id'], broker.identity)
                raise ValueError('failed transaction')
            broker.request.side_effect = arm
            with self.assertRaises(ValueError): protection.arm(broker, 7)
            self.assertTrue(protection.active)
            broker.request.side_effect = ValueError('release failed')
            with self.assertRaises(ValueError): protection.release(broker)
            self.assertTrue(protection.active)
            broker.request.side_effect = None
            broker.request.return_value = True
            protection.release(broker)
            self.assertFalse(protection.active)

    def test_abnormal_exit_keeps_protection_until_explicit_stop(self):
        service = ApplicationService(Mock())
        service.analytics = None
        service.stop_requested.clear()
        service.session.protection = Mock(active=True)
        service.session.core = Mock()
        service.session.core.process.poll.return_value = 1
        def stop(): service.session.core = None
        service.session.stop = Mock(side_effect=stop)
        service._handle_core_exited({'generation': service.session.generation})
        service.session.protection.release.assert_not_called()
        service._handle_stop({})
        service.session.protection.release.assert_called_once_with(service.session.broker)

    def test_protected_core_is_not_started_before_network_journal_and_filter(self):
        broker = Mock(identity='b' * 32, closed=threading.Event())
        broker.request.side_effect = lambda action, **fields: {'pid': 123, 'serial': 9, 'core_start': 456} if action == 'prepare' else True
        steps = []
        protection = Mock()
        protection.arm.side_effect = lambda *args: steps.append('filter')
        def journal(pid):
            self.assertEqual([c.args[0] for c in broker.request.call_args_list], ['prepare'])
            steps.append('journal')
        core = ElevatedCore(broker, {}, None, journal, protection)
        self.assertEqual(steps, ['journal', 'filter'])
        self.assertEqual([c.args[0] for c in broker.request.call_args_list], ['prepare', 'start'])
        core.close()
        protection.release.assert_not_called()

    def test_local_mode_preserves_dormant_preference_without_enabling_global_filters(self):
        settings = dict(DEFAULTS, kill_switch=True)
        self.assertFalse(enabled(settings))
        self.assertFalse(connection_settings(settings)['kill_switch'])
        config = {'fixture': True}
        self.assertIs(configure(config, settings), config)

    @unittest.skipUnless(CORE.is_file(), 'Xray required')
    def test_system_protection_bootstraps_only_server_names_and_uses_core_dns(self):
        _, config = build_config('vless://00000000-0000-4000-8000-000000000001@server.example.com:443?security=tls')
        settings = dict(DEFAULTS, capture='system', preset='all', kill_switch=True)
        config = configure(apply_routing(config, settings), settings, ['192.0.2.53'])
        bootstrap = config['dns']['servers'][0]
        self.assertEqual(bootstrap['domains'], ['full:server.example.com'])
        self.assertTrue(bootstrap['skipFallback'])
        self.assertTrue(bootstrap['finalQuery'])
        self.assertEqual(config['outbounds'][0]['streamSettings']['sockopt']['domainStrategy'], 'UseIP')
        validate_config(config)

    def test_recovery_uses_old_protected_component_and_preserves_marker_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            protection = KillSwitch(SecureFile(Path(directory) / 'protection', cipher=lambda data, decrypt=False: data))
            protection.file.write({'helper_id': 'a' * 32})
            previous = Mock(identity='b' * 32, closed=threading.Event())
            with patch('yukiwire.broker.Broker') as factory:
                factory.return_value.request.side_effect = ValueError('not cleaned')
                with self.assertRaises(ValueError): protection.release(previous)
                factory.assert_called_once_with(component_identity='a' * 32)
                self.assertTrue(protection.active)
                factory.return_value.close.assert_called_once()


if __name__ == '__main__': unittest.main()
