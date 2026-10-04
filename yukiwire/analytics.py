"""Bounded, user-encrypted session history. No profiles, hosts or request data."""
import os
import re
import time
import uuid

from .network import journal_lock, process_identity
from .paths import STATE
from .storage import SecureFile

COUNTERS = ('sessions', 'duration', 'download_bytes', 'upload_bytes', 'direct_bytes',
            'failures', 'reconnects', 'checks', 'latency_sum')
SAMPLE_COUNTERS = COUNTERS[1:]


def empty():
    return {'version': 1, 'total': dict.fromkeys(COUNTERS, 0), 'recent': [], 'active': None}


def number(value):
    return max(0, min(2**63 - 1, int(value or 0)))


class Analytics:
    def __init__(self, file=None):
        self.file = file or SecureFile(STATE / 'analytics.dpapi')
        self.current = None
        self.last_save = 0

    def _read(self):
        value = self.file.read(empty())
        if value.get('version') != 1:
            raise ValueError('Unknown analytics format')
        return value

    @staticmethod
    def _archive(value):
        active = value['active']
        if not active:
            return
        value['total']['sessions'] += 1
        for key in SAMPLE_COUNTERS:
            value['total'][key] += number(active.get(key))
        value['recent'] = [active] + value['recent'][:99]
        value['active'] = None

    def initialize(self):
        with journal_lock(self.file.path):
            value = self._read()
            active = value.get('active')
            if active and process_identity(active['owner']) != active['owner_created']:
                active['interrupted'] = True
                active['ended'] = active['updated']
                self._archive(value)
                self.file.write(value)
        return self.overview()

    def begin(self, capture, preset):
        with journal_lock(self.file.path):
            value = self._read()
            if value['active']:
                active = value['active']
                if process_identity(active['owner']) == active['owner_created']:
                    raise ValueError('Session history already belongs to a running process')
                active['ended'] = active['updated']
                active['interrupted'] = True
                self._archive(value)
            self.current = uuid.uuid4().hex
            value['active'] = dict.fromkeys(SAMPLE_COUNTERS, 0)
            value['active'].update(id=self.current, owner=os.getpid(), owner_created=process_identity(os.getpid()),
                                   started=int(time.time()), updated=int(time.time()), capture=capture,
                                   preset=preset, ended=None, interrupted=False, country=None)
            self.file.write(value)
            self.last_save = time.monotonic()

    def update(self, stats=None, latency=None, country=None, force=False):
        if not self.current:
            return
        # Probe and country results are infrequent; traffic checkpoints are every 10 s.
        if not force and latency is None and country is None and time.monotonic() - self.last_save < 10:
            return
        with journal_lock(self.file.path):
            value = self._read()
            active = value.get('active')
            if not active or active['id'] != self.current:
                return
            if stats:
                for source, target in [('uptime', 'duration'), ('download_bytes', 'download_bytes'),
                                       ('upload_bytes', 'upload_bytes'), ('direct_bytes', 'direct_bytes'),
                                       ('failures', 'failures'), ('reconnects', 'reconnects')]:
                    if source in stats:
                        active[target] = max(number(active.get(target)), number(stats[source]))
            if latency is not None:
                active['checks'] += 1
                active['latency_sum'] += number(latency)
            if country is not None and re.fullmatch('[A-Z]{2}', str(country)):
                active['country'] = country
            active['updated'] = int(time.time())
            self.file.write(value)
            self.last_save = time.monotonic()

    def finish(self, stats):
        if not self.current:
            return
        self.update(stats, force=True)
        with journal_lock(self.file.path):
            value = self._read()
            if value.get('active') and value['active']['id'] == self.current:
                value['active']['ended'] = int(time.time())
                self._archive(value)
                self.file.write(value)
            self.current = None

    def overview(self):
        with journal_lock(self.file.path):
            value = self._read()
            total = {key: number(value['total'].get(key)) for key in COUNTERS}
            if value.get('active'):
                total['sessions'] += 1
                for key in SAMPLE_COUNTERS:
                    total[key] += number(value['active'].get(key))
            recent = [{key: row.get(key) for key in ('started', 'ended', 'duration', 'download_bytes',
                      'upload_bytes', 'reconnects', 'interrupted', 'country')} for row in value['recent'][:8]]
            total['average_https_ms'] = round(total['latency_sum'] / total['checks']) if total['checks'] else None
            total.pop('latency_sum')
            return {'total': total, 'recent': recent}
