import os
from pathlib import Path
import tempfile
import unittest

from yukiwire.network import process_command
from yukiwire.startup import register, unregister


@unittest.skipUnless(os.name == 'nt', 'Windows Task Scheduler integration')
class StartupIntegrationTests(unittest.TestCase):
    def test_real_logon_task_uses_security_identity_and_removes_idempotently(self):
        with tempfile.TemporaryDirectory(prefix='yukiwire-startup-integration-') as temporary:
            journal = Path(temporary) / 'network-lease.dpapi'
            command = process_command('yukiwire.recovery', '--journal', journal)
            try:
                register(journal, command, 'system')
            finally:
                unregister(journal, command)
            unregister(journal, command)
