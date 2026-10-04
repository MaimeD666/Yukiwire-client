"""Real Windows handles and process deaths, backed by a fake network only."""
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from yukiwire.network import process_identity
from yukiwire.storage import atomic_write


@unittest.skipUnless(os.name == 'nt', 'Windows process handles required')
class WatchdogIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.journal = self.directory / 'journal.json'
        self.os_state = self.directory / 'fake-os.json'
        self.original = {'flags': 9, 'server': 'disabled:3128', 'bypass': 'local', 'pac': 'https://example.invalid/pac'}
        self.desired = {'flags': 3, 'server': '127.0.0.1:11809', 'bypass': '<local>', 'pac': ''}
        self.processes = []
        for _ in range(2):
            self.processes.append(subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                                 creationflags=subprocess.CREATE_NO_WINDOW))
        self.owner, self.core = self.processes
        self.record = {'version': 1, 'kind': 'proxy', 'lease_id': 'first',
                       'owner': self.owner.pid, 'owner_start': process_identity(self.owner.pid),
                       'core': self.core.pid, 'core_start': process_identity(self.core.pid),
                       'original': self.original, 'desired': self.desired, 'phase': 'applied'}
        self.write(self.journal, self.record)
        self.write(self.os_state, self.desired)

    @staticmethod
    def write(path, value):
        atomic_write(path, json.dumps(value).encode())

    def launch(self, expect_ready=True):
        worker = Path(__file__).parent / 'fixtures' / 'watchdog_worker.py'
        process = subprocess.Popen([sys.executable, str(worker), '--journal', str(self.journal)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
        self.processes.append(process)
        lines = queue.Queue()
        threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True).start()
        line = lines.get(timeout=5)
        self.assertEqual(line.strip(), b'READY' if expect_ready else b'')
        return process

    def tearDown(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()
        self.temp.cleanup()

    def assert_restored(self, process):
        process.wait(timeout=5)
        self.assertFalse(self.journal.exists())
        self.assertEqual(json.loads(self.os_state.read_bytes()), self.original)

    def test_core_crash_restores_original_settings(self):
        watcher = self.launch()
        self.core.terminate()
        self.assert_restored(watcher)

    def test_owner_crash_restores_original_settings(self):
        watcher = self.launch()
        self.owner.terminate()
        self.assert_restored(watcher)

    def test_active_processes_keep_the_lease(self):
        watcher = self.launch()
        time.sleep(.35)
        self.assertIsNone(watcher.poll())
        self.assertTrue(self.journal.exists())
        self.assertEqual(json.loads(self.os_state.read_bytes()), self.desired)

    def test_new_foreign_proxy_is_preserved_after_crash(self):
        watcher = self.launch()
        foreign = dict(self.desired, server='127.0.0.1:2080')
        self.write(self.os_state, foreign)
        self.core.terminate()
        watcher.wait(timeout=5)
        self.assertTrue(self.journal.exists())
        self.assertEqual(json.loads(self.os_state.read_bytes()), foreign)

    def test_old_watcher_cannot_remove_new_connection(self):
        watcher = self.launch()
        self.write(self.journal, dict(self.record, lease_id='second'))
        self.core.terminate()
        watcher.wait(timeout=5)
        self.assertEqual(json.loads(self.journal.read_bytes())['lease_id'], 'second')
        self.assertEqual(json.loads(self.os_state.read_bytes()), self.desired)

    def test_wrong_creation_time_refuses_to_arm(self):
        self.write(self.journal, dict(self.record, core_start=self.record['core_start'] + 1))
        watcher = self.launch(expect_ready=False)
        watcher.wait(timeout=5)
        self.assertTrue(self.journal.exists())
        self.assertEqual(json.loads(self.os_state.read_bytes()), self.desired)
