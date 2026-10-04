import hashlib
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from yukiwire.geodata import RuleSets, match_site, match_ip


def integer(value):
    data = bytearray()
    while value > 127:
        data.append((value & 127) | 128)
        value >>= 7
    data.append(value)
    return bytes(data)


def field(number, data):
    if isinstance(data, str):
        data = data.encode()
    return integer(number * 8 + 2) + integer(len(data)) + data


def geo_fixture():
    domain = integer(1 * 8) + integer(2) + field(2, 'blocked.ru')
    site = field(1, field(1, 'RU-BLOCKED') + field(2, domain))
    cidr = field(1, ipaddress.ip_address('192.0.2.0').packed) + integer(2 * 8) + integer(24)
    ip = field(1, field(1, 'RU') + field(2, cidr))
    return {'geosite.dat': site, 'geoip.dat': ip}


class GeoDataTests(unittest.TestCase):
    def test_active_data_tampering_is_rejected_before_connect(self):
        with tempfile.TemporaryDirectory() as temporary:
            manager = RuleSets(temporary)
            with patch('yukiwire.geodata.download', self._download()):
                manager.update(lambda tags: None)
            folder = Path(temporary) / manager.metadata()['commit']
            (folder / 'geosite.dat').write_bytes(b'tampered')
            with self.assertRaises(ValueError):
                manager.tags()

    def test_real_match_semantics_for_subdomains_and_cidr(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = {}
            for name, data in geo_fixture().items():
                path = Path(temporary) / name
                path.write_bytes(data)
                paths[name] = path
            self.assertTrue(match_site(paths['geosite.dat'], 'ru-blocked', 'a.blocked.ru'))
            self.assertFalse(match_site(paths['geosite.dat'], 'ru-blocked', 'notblocked.ru'))
            self.assertTrue(match_ip(paths['geoip.dat'], 'ru', ipaddress.ip_address('192.0.2.88')))
            self.assertFalse(match_ip(paths['geoip.dat'], 'ru', ipaddress.ip_address('192.0.3.1')))

    def _download(self, tampered=False):
        fixtures = geo_fixture()
        commit = 'a' * 40
        tree = {'tree': [{'path': name, 'type': 'blob', 'sha': hashlib.sha1(('blob %s\0' % len(data)).encode() + data).hexdigest()} for name, data in fixtures.items()]}
        def download(url, *args):
            if '/git/ref/' in url:
                return json.dumps({'object': {'sha': commit}}).encode()
            if '/git/commits/' in url:
                return json.dumps({'tree': {'sha': 'b' * 40}}).encode()
            if '/git/trees/' in url:
                return json.dumps(tree).encode()
            data = fixtures[url.rsplit('/', 1)[1]]
            return data + b'corrupted' if tampered else data
        return download

    def test_corrupt_download_does_not_activate(self):
        with tempfile.TemporaryDirectory() as temporary:
            manager = RuleSets(temporary)
            with patch('yukiwire.geodata.download', self._download(tampered=True)):
                with self.assertRaises(ValueError):
                    manager.update(lambda tags: None)
            self.assertFalse(manager.active.exists())

    def test_core_validation_failure_keeps_previous_active(self):
        with tempfile.TemporaryDirectory() as temporary:
            manager = RuleSets(temporary)
            def reject(tags):
                raise ValueError('core validation failed')
            with patch('yukiwire.geodata.download', self._download()):
                with self.assertRaises(ValueError):
                    manager.update(reject)
            self.assertFalse(manager.active.exists())

    def test_first_update_can_rollback_to_builtins(self):
        with tempfile.TemporaryDirectory() as temporary:
            manager = RuleSets(temporary)
            with patch('yukiwire.geodata.download', self._download()):
                manager.update(lambda tags: None)
            self.assertTrue(manager.metadata()['custom'])
            manager.rollback(lambda tags: None)
            self.assertFalse(manager.metadata()['custom'])
