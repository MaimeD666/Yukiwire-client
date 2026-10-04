import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from yukiwire.analytics import Analytics


class MemoryFile:
    def __init__(self, path):
        self.path = path
        self.value = None

    def read(self, default):
        return copy.deepcopy(self.value if self.value is not None else default)

    def write(self, value):
        self.value = copy.deepcopy(value)


class AnalyticsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.file = MemoryFile(Path(self.directory.name) / 'analytics.dpapi')
        self.history = Analytics(self.file)

    def tearDown(self):
        self.directory.cleanup()

    def test_final_counters_never_decrease_and_finish_is_idempotent(self):
        self.history.begin('local', 'all')
        self.history.update({'download_bytes': 1000, 'uptime': 20}, latency=250, force=True)
        self.history.finish({'download_bytes': 900, 'uptime': 25, 'reconnects': 1})
        self.history.finish({'download_bytes': 900, 'uptime': 25})
        data = self.history.overview()
        self.assertEqual(data['total']['sessions'], 1)
        self.assertEqual(data['total']['download_bytes'], 1000)
        self.assertEqual(data['total']['duration'], 25)
        self.assertEqual(data['total']['average_https_ms'], 250)

    def test_crash_keeps_last_checkpoint_and_marks_interruption_once(self):
        self.history.begin('local', 'all')
        self.history.update({'download_bytes': 2048, 'uptime': 18}, force=True)
        with patch('yukiwire.analytics.process_identity', return_value=None):
            recovered = Analytics(self.file)
            recovered.initialize()
            recovered.initialize()
        data = recovered.overview()
        self.assertEqual(data['total']['sessions'], 1)
        self.assertEqual(data['total']['download_bytes'], 2048)
        self.assertTrue(data['recent'][0]['interrupted'])
        self.assertEqual(data['recent'][0]['duration'], 18)

    def test_live_owner_is_preserved_and_old_store_cannot_finish_new_session(self):
        self.history.begin('local', 'all')
        owner = self.file.value['active']['owner_created']
        with patch('yukiwire.analytics.process_identity', return_value=owner):
            other = Analytics(self.file)
            other.initialize()
            with self.assertRaises(ValueError):
                other.begin('local', 'all')
        self.file.value['active']['id'] = 'a-new-session'
        self.history.finish({'download_bytes': 99})
        self.assertEqual(self.file.value['active']['id'], 'a-new-session')
        self.assertEqual(self.file.value['total']['sessions'], 0)

    def test_bounded_recent_list_preserves_all_time_totals_and_public_privacy(self):
        for _ in range(103):
            self.history.begin('local', 'all')
            self.history.finish({'download_bytes': 512})
        data = self.history.overview()
        self.assertEqual(len(self.file.value['recent']), 100)
        self.assertEqual(data['total']['sessions'], 103)
        self.assertEqual(data['total']['download_bytes'], 103 * 512)
        self.assertEqual(len(data['recent']), 8)
        self.assertNotIn('owner', str(data))
        self.assertNotIn('owner_created', str(data))
