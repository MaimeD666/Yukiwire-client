import json
import subprocess
import time
from .paths import CORE


def enable_metrics(config):
    config['stats'] = {}
    config.pop('metrics', None)
    config['api'] = {'tag': 'yukiwire-stats', 'listen': '127.0.0.1:11811', 'services': ['StatsService']}
    policy = config.setdefault('policy', {}).setdefault('system', {})
    policy.update({'statsInboundUplink': True, 'statsInboundDownlink': True, 'statsOutboundUplink': True, 'statsOutboundDownlink': True})
    return config


class Telemetry:
    def __init__(self):
        self.last = None
        self.last_direct = 0

    def sample(self):
        result = subprocess.run([str(CORE), 'api', 'statsquery', '--server=127.0.0.1:11811', '-pattern', 'traffic', '-timeout', '1'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:
            raise ValueError('Метрики временно недоступны.')
        payload = json.loads(result.stdout)
        stats = {item['name']: int(item.get('value', 0)) for item in payload.get('stat', [])}
        incoming = ('local-http', 'local-socks', 'yukiwire-tun', 'yukiwire-check')
        up = sum(stats.get('inbound>>>%s>>>traffic>>>uplink' % key, 0) for key in incoming)
        down = sum(stats.get('inbound>>>%s>>>traffic>>>downlink' % key, 0) for key in incoming)
        now = time.monotonic()
        upload_rate = download_rate = 0
        if self.last:
            elapsed = max(.1, now - self.last[0])
            upload_rate = max(0, round((up - self.last[1]) / elapsed))
            download_rate = max(0, round((down - self.last[2]) / elapsed))
        self.last = (now, up, down)
        self.last_direct = sum(stats.get('outbound>>>yukiwire-direct>>>traffic>>>' + direction, 0) for direction in ('uplink', 'downlink'))
        return {'upload_bytes': up, 'download_bytes': down, 'upload_bps': upload_rate, 'download_bps': download_rate,
                'direct_bytes': self.last_direct,
                }
