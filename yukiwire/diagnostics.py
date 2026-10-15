"""Opt-in bounded technical events. Unknown fields and raw strings are discarded."""
from collections import deque
import json
from pathlib import Path
import threading
import time

from .paths import STATE

EVENTS = frozenset(('ready starting started stopped reconnecting core_exited probe_result error recovered '
                    'settings environment rules_updating rules_updated updates_checking updates_checked '
                    'subscription_updating subscription_updated profiles_checking profile_latency profiles_checked '
                    'core_log').split())
OPERATIONS = frozenset(('start stop probe save_settings save_profile check_sites update_rules rollback_rules '
                       'recover_network check_updates update_subscription import_profiles host').split())
CATEGORIES = frozenset(('tls timeout refused permission reset dns transport connection config other').split())
MODULES = ('transport/internet/reality', 'transport/internet/tls', 'transport/internet/splithttp',
           'transport/internet/websocket', 'transport/internet/grpc', 'transport/internet/tcp',
           'proxy/vless', 'proxy/vmess', 'proxy/trojan', 'proxy/shadowsocks', 'proxy/tun', 'app/dns', 'app/router')


def core_event(text):
    """Extract known categories, never redact-and-forward arbitrary core stderr."""
    lower = text.lower()
    category = next((name for name, words in (
        ('tls', ('certificate', 'x509', 'handshake', 'reality')),
        ('dns', ('dns', 'lookup', 'resolve')),
        ('timeout', ('timeout', 'deadline')),
        ('refused', ('refused',)), ('permission', ('permission', 'forbidden', 'access denied')),
        ('reset', ('connection reset',)), ('config', ('configuration', 'config:')),
        ('transport', ('transport',)), ('connection', ('failed to', 'connection')))
        if any(word in lower for word in words)), 'other')
    level = next((name for name in ('error', 'warning', 'info', 'debug') if '[' + name + ']' in lower), 'info')
    module = next((name for name in MODULES if name in lower), 'core')
    return {'category': category, 'level': level, 'module': module}


class DebugTrace:
    def __init__(self, directory=STATE, limit=256 * 1024):
        self.path = Path(directory) / 'debug-trace.jsonl'
        self.previous = self.path.with_suffix('.previous.jsonl')
        self.limit = limit
        self.enabled = False
        self.lock = threading.RLock()

    @staticmethod
    def safe(event, values):
        if event not in EVENTS:
            return None
        record = {'event': event}
        for key, allowed in (('capture', {'local', 'system', 'tun'}),
                             ('preset', {'all', 'selected', 'ru-direct', 'original'}),
                             ('operation', OPERATIONS), ('category', CATEGORIES),
                             ('level', {'debug', 'info', 'warning', 'error'}), ('module', set(MODULES) | {'core'})):
            if isinstance(values.get(key), str) and values[key] in allowed:
                record[key] = values[key]
        for key in ('active', 'reconnected', 'restored', 'conflict', 'settings_pending', 'check_failed', 'other_proxy', 'other_vpn'):
            if type(values.get(key)) is bool:
                record[key] = values[key]
        for key in ('elapsed_ms', 'failed_checks', 'reconnects', 'code', 'count'):
            if type(values.get(key)) in (int, float) and -2147483648 <= values[key] <= 2147483647:
                record[key] = round(values[key], 2)
        return record

    def record(self, event, **values):
        if not self.enabled:
            return
        record = self.safe(event, values)
        if record is None:
            return
        record['time'] = round(time.time(), 3)
        data = (json.dumps(record, ensure_ascii=True) + '\n').encode()
        try:
            with self.lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size + len(data) > self.limit:
                    self.path.replace(self.previous)
                with self.path.open('ab') as output:
                    output.write(data)
        except OSError:
            pass  # Logging must never affect networking or recovery.

    def export(self):
        result = deque(maxlen=1000)
        with self.lock:
            for path in (self.previous, self.path):
                try:
                    if path.stat().st_size > self.limit:
                        continue
                    for line in path.read_text(encoding='utf-8').splitlines():
                        try:
                            value = json.loads(line)
                            record = self.safe(value.get('event'), value)
                            if record:
                                timestamp = value.get('time')
                                if type(timestamp) in (float, int) and 0 <= timestamp < 100000000000:
                                    record['time'] = timestamp
                                result.append(record)
                        except (ValueError, TypeError, AttributeError):
                            pass
                except (OSError, UnicodeError):
                    pass
        return list(result)

    def clear(self):
        with self.lock:
            self.path.unlink(missing_ok=True)
            self.previous.unlink(missing_ok=True)
