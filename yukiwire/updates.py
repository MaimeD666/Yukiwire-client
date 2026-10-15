"""User-requested release discovery; never execute downloaded code."""
import json
import re
from .geodata import download
from .version import VERSION, REPOSITORY


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r'v?\d{1,5}\.\d{1,5}(?:\.\d{1,5})?', value):
        raise ValueError('Источник вернул неподдерживаемый номер версии.')
    parts = tuple(map(int, value.removeprefix('v').split('.')))
    return parts + (0,) * (3 - len(parts))


def latest_release(proxy_port=None):
    payload = json.loads(download('https://api.github.com/repos/' + REPOSITORY + '/releases/latest',
                                  proxy_port, 1024 * 1024))
    version = payload.get('tag_name')
    available = version_tuple(version) > version_tuple(VERSION)
    if payload.get('draft') or payload.get('prerelease'):
        raise ValueError('Источник вернул предварительную сборку вместо стабильной.')
    return {'current': VERSION, 'latest': version.removeprefix('v'), 'available': available}
