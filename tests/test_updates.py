import json
import unittest
from unittest.mock import patch
from yukiwire.updates import latest_release, version_tuple


class UpdateTests(unittest.TestCase):
    def test_numeric_versions_do_not_use_lexicographic_order(self):
        self.assertGreater(version_tuple('v0.10'), version_tuple('0.9.5'))
        self.assertEqual(version_tuple('v0.4'), version_tuple('0.4.0'))

    def test_release_data_cannot_supply_executable_links_or_prereleases(self):
        payload = dict(tag_name='v99.0', html_url='file:///untrusted.exe')
        with patch('yukiwire.updates.download', return_value=json.dumps(payload).encode()) as fetch:
            result = latest_release(32123)
            self.assertTrue(result['available'])
            self.assertEqual(set(result), {'current', 'latest', 'available'})
            self.assertEqual(fetch.call_args.args[1], 32123)
        payload['prerelease'] = True
        with patch('yukiwire.updates.download', return_value=json.dumps(payload).encode()):
            with self.assertRaises(ValueError):
                latest_release()
