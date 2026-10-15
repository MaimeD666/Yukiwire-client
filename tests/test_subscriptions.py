import base64
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from yukiwire import subscriptions
from yukiwire.storage import ProfileStore

LINK = 'vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls#public-fixture'


class SubscriptionTests(unittest.TestCase):
    def test_plain_and_base64_lists_validate_every_profile_and_deduplicate(self):
        for text in (LINK + '\n' + LINK, base64.b64encode((LINK + '\n' + LINK).encode()).decode()):
            validate = Mock()
            result = subscriptions.profiles(text, validate)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['text'], LINK)
            validate.assert_called_once()

    def test_invalid_subscription_never_replaces_old_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProfileStore(directory, cipher=lambda data, decrypt=False: data)
            old = subscriptions.profiles(LINK, lambda config: None)
            identity = store.update_subscription('https://example.com/private-token', 'Test', old)
            before = store.file.path.read_bytes()
            with self.assertRaises(ValueError):
                entries = subscriptions.profiles(LINK + '\nunsupported://private', lambda config: None)
                store.update_subscription('https://example.com/private-token', 'Test', entries, identity)
            self.assertEqual(store.file.path.read_bytes(), before)
            self.assertNotIn('private-token', str(store.public()))

    def test_refresh_preserves_ids_selection_and_manual_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ProfileStore(directory, cipher=lambda data, decrypt=False: data)
            manual = store.save(LINK + '-manual', 'Manual', 'vless')
            entries = subscriptions.profiles(LINK, lambda config: None)
            identity = store.update_subscription('https://example.com/sub', 'Subscription', entries)
            first = store.public()
            self.assertEqual(first['selected'], manual)
            self.assertEqual(store.update_subscription('https://example.com/sub', 'Subscription', entries), identity)
            self.assertEqual(store.public()['profiles'], first['profiles'])
            store.remove_subscription(identity)
            self.assertEqual(store.public()['profiles'], first['profiles'])
            self.assertEqual(store.public()['subscriptions'], [])

    def test_https_redirect_cannot_downgrade_to_http(self):
        connection = Mock()
        connection.getresponse.return_value.status = 302
        connection.getresponse.return_value.getheader.return_value = 'http://example.com/private-token'
        with patch('yukiwire.subscriptions.http.client.HTTPSConnection', return_value=connection):
            with self.assertRaises(ValueError): subscriptions.download('https://example.com/sub', 12345)
        connection.set_tunnel.assert_called_once_with('example.com', 443)
        connection.close.assert_called_once()

    def test_untrusted_formats_and_credentials_are_rejected(self):
        for url in ('http://example.com', 'file:///private', 'https://user:secret@example.com', 'https://example.com:bad-token'):
            with self.subTest(url=url), self.assertRaises(ValueError) as error:
                subscriptions.validate_url(url)
            self.assertNotIn('bad-token', str(error.exception))
        with self.assertRaises(ValueError): subscriptions.profiles('<html>not a subscription</html>', Mock())
