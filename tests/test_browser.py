from pathlib import Path
import unittest
from unittest.mock import patch
from yukiwire.browser import command, open_browser


class BrowserTests(unittest.TestCase):
    def test_launch_uses_separate_profile_and_explicit_proxy_without_fallback(self):
        args = command(Path('C:/Chrome/chrome.exe'), Path('C:/Yukiwire/runtime/browser/chrome'))
        self.assertIn('--proxy-server=http://127.0.0.1:11809', args)
        self.assertTrue(any(arg.startswith('--user-data-dir=') for arg in args))
        self.assertIn('--disable-quic', args)
        self.assertFalse(any('direct://' in arg for arg in args))
        self.assertEqual(args[-1], 'https://chatgpt.com/')

    def test_missing_browser_does_not_open_unproxied_default_browser(self):
        with patch('yukiwire.browser.browser_path', side_effect=ValueError('missing')), patch('yukiwire.browser.subprocess.Popen') as spawn:
            with self.assertRaises(ValueError):
                open_browser()
            spawn.assert_not_called()
