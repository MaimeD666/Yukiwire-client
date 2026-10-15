import threading
import unittest
from unittest.mock import Mock, patch

from yukiwire.backend import ApplicationService


class ProfileTaskTests(unittest.TestCase):
    def threads(self):
        original = threading.Thread
        workers = []
        def create(*args, **kwargs):
            worker = original(*args, **kwargs)
            workers.append(worker)
            return worker
        return workers, patch('yukiwire.backend.threading.Thread', side_effect=create)

    def test_subscription_fetch_does_not_hold_state_lock_and_stop_remains_responsive(self):
        service = ApplicationService(Mock(), profiles=Mock())
        service.session.stop = Mock()
        service.analytics = None
        entered, finish = threading.Event(), threading.Event()
        workers, threads = self.threads()
        def download(*args):
            entered.set()
            self.assertTrue(finish.wait(5))
            return 'public fixture'
        with threads, patch('yukiwire.backend.subscriptions.download', side_effect=download), \
                patch('yukiwire.backend.subscriptions.profiles', return_value=[{'text': 'fixture'}]):
            try:
                service._command({'action': 'update_subscription', 'url': 'https://example.com/private-fixture-token'})
                self.assertTrue(entered.wait(3))
                service._command({'action': 'stop'})
                service.session.stop.assert_called_once()
                self.assertTrue(service.subscription_busy)
            finally:
                finish.set()
                for worker in workers: worker.join(5)
        service.profiles.update_subscription.assert_called_once()
        self.assertFalse(service.subscription_busy)
        self.assertNotIn('private-fixture-token', str(service._emit_target.call_args_list))

    def test_late_subscription_completion_after_close_preserves_saved_profiles(self):
        service = ApplicationService(Mock(), profiles=Mock())
        workers, threads = self.threads()
        def download(*args):
            service.closing.set()
            return 'public fixture'
        with threads, patch('yukiwire.backend.subscriptions.download', side_effect=download), \
                patch('yukiwire.backend.subscriptions.profiles', return_value=[{'text': 'fixture'}]):
            service._command({'action': 'update_subscription', 'url': 'https://example.com/sub'})
            for worker in workers: worker.join(5)
        service.profiles.update_subscription.assert_not_called()
        self.assertFalse(service.subscription_busy)

    def test_latency_probe_uses_separate_local_session_and_never_stops_active_core(self):
        service = ApplicationService(Mock(), profiles=Mock())
        active = service.session.core = Mock()
        service.profiles.get.side_effect = lambda identity: {'id': identity, 'text': 'public fixture'}
        probe = Mock()
        probe.probe.return_value = {'elapsed_ms': 123}
        workers, threads = self.threads()
        with threads, patch('yukiwire.backend.Session', return_value=probe):
            service._command({'action': 'check_profiles', 'profile_ids': ['one', 'one']})
            for worker in workers: worker.join(5)
        self.assertIs(service.session.core, active)
        active.close.assert_not_called()
        self.assertEqual(probe.start.call_args.args[1]['capture'], 'local')
        probe.stop.assert_called_once()
        self.assertEqual(service.profile_latencies['one']['elapsed_ms'], 123)
        self.assertFalse(service.profile_check_busy)

    def test_unconfirmed_probe_cleanup_aborts_remaining_profiles(self):
        service = ApplicationService(Mock(), profiles=Mock())
        service.profiles.get.side_effect = lambda identity: {'id': identity, 'text': 'public fixture'}
        probe = Mock()
        probe.probe.return_value = {'elapsed_ms': 123}
        probe.stop.side_effect = OSError('synthetic-secret-must-not-escape')
        workers, threads = self.threads()
        with threads, patch('yukiwire.backend.Session', return_value=probe) as factory:
            service._command({'action': 'check_profiles', 'profile_ids': ['one', 'two']})
            for worker in workers: worker.join(5)
        factory.assert_called_once()
        self.assertEqual(service.profile_latencies, {})
        self.assertFalse(service.profile_check_busy)
        self.assertNotIn('synthetic-secret', str(service._emit_target.call_args_list))
