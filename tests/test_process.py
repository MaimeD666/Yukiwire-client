import subprocess
import unittest
from unittest.mock import Mock

from yukiwire.process import CoreProcess


class CoreCleanupTests(unittest.TestCase):
    def core(self):
        core = CoreProcess.__new__(CoreProcess)
        core.process = Mock()
        core.process.poll.return_value = None
        core.process.stdin.closed = core.process.stdout.closed = False
        core.handle = 123
        core.api = Mock()
        core.api.CloseHandle.return_value = True
        core.reader = Mock()
        return core

    def test_failed_terminate_still_closes_job_and_waits_for_its_child(self):
        core = self.core()
        core.process.terminate.side_effect = OSError('process race')
        def close_job(handle):
            self.assertEqual(handle, 123)
            core.process.poll.return_value = 1
            return True
        core.api.CloseHandle.side_effect = close_job
        core.close()
        self.assertIsNone(core.handle)
        core.process.wait.assert_called_once_with(timeout=3)
        core.process.stdout.close.assert_called_once()
        core.close()
        core.api.CloseHandle.assert_called_once()

    def test_timeout_releases_job_before_retrying_and_never_blocks_on_live_pipe(self):
        core = self.core()
        core.process.wait.side_effect = subprocess.TimeoutExpired('test-child', 3)
        with self.assertRaises(subprocess.TimeoutExpired):
            core.close()
        core.api.CloseHandle.assert_called_once_with(123)
        core.process.kill.assert_called_once()
        core.process.stdout.close.assert_not_called()
        core.process.stdin.close.assert_not_called()

    def test_partial_constructor_without_child_releases_job(self):
        core = self.core()
        core.process = core.reader = None
        core.close()
        core.api.CloseHandle.assert_called_once_with(123)
