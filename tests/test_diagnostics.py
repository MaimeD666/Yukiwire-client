import json
from pathlib import Path
import tempfile
import unittest
from yukiwire.diagnostics import DebugTrace, core_event
from yukiwire.routing import DEFAULTS, connection_settings


class DiagnosticTests(unittest.TestCase):
    def test_disabled_logging_creates_no_file(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = DebugTrace(directory)
            trace.record('started', capture='tun')
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_raw_credentials_hosts_addresses_and_unknown_fields_never_persist(self):
        secret = 'private.invalid 192.0.2.88 2001:db8::88 11111111-2222-4333-8444-555555555555 token=secret-fixture'
        with tempfile.TemporaryDirectory() as directory:
            trace = DebugTrace(directory); trace.enabled = True
            trace.record('error', message=secret, profile=secret, operation=secret, category=secret, elapsed_ms=12)
            trace.record('core_log', **core_event('[Warning] proxy/vless: failed TLS handshake to ' + secret))
            data = trace.path.read_text()
            for value in secret.split(): self.assertNotIn(value, data)
            self.assertIn('"category": "tls"', data)
            self.assertIn('"module": "proxy/vless"', data)
            self.assertEqual(trace.export()[0]['elapsed_ms'], 12)

    def test_rotation_and_export_revalidate_even_a_modified_log(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = DebugTrace(directory, limit=512); trace.enabled = True
            for _ in range(50): trace.record('started', capture='tun', reconnected=True)
            self.assertLessEqual(trace.path.stat().st_size, 512)
            self.assertLessEqual(trace.previous.stat().st_size, 512)
            trace.path.write_text(json.dumps({'event': 'error', 'message': 'secret-fixture', 'operation': 'start'}) + '\n')
            self.assertNotIn('secret-fixture', str(trace.export()))
            trace.clear()
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_debug_toggle_does_not_reconnect(self):
        self.assertEqual(connection_settings(DEFAULTS), connection_settings(dict(DEFAULTS, debug_logging=True)))
