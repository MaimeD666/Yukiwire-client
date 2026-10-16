import json
import http.client
import time
from .endpoints import Endpoint, STATS_PORT


def enable_metrics(config, endpoint=None):
    endpoint = endpoint or Endpoint(STATS_PORT)
    config['stats'] = {}
    config.pop('api', None)
    config['metrics'] = {'tag': 'yukiwire-stats'}
    config['inbounds'].append(endpoint.inbound('yukiwire-metrics'))
    config.setdefault('routing', {}).setdefault('rules', []).insert(0, {
        'type': 'field', 'inboundTag': ['yukiwire-metrics'], 'outboundTag': 'yukiwire-stats'})
    policy = config.setdefault('policy', {}).setdefault('system', {})
    policy.update({'statsInboundUplink': True, 'statsInboundDownlink': True, 'statsOutboundUplink': True, 'statsOutboundDownlink': True})
    return config


class Telemetry:
    def __init__(self, endpoint=None):
        self.endpoint = endpoint or Endpoint(STATS_PORT)
        self.last = None
        self.last_direct = 0

    def sample(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.endpoint.port, timeout=1)
        try:
            connection.request('GET', 'http://metrics.internal/debug/vars', headers=self.endpoint.headers)
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError('Метрики временно недоступны.')
            data = response.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise ValueError('Слишком большой ответ метрик.')
            stats = json.loads(data)['stats']
        finally:
            connection.close()
        incoming = ('local-http', 'local-socks', 'yukiwire-tun', 'yukiwire-check')
        inbound = stats.get('inbound', {})
        up = sum(int(inbound.get(key, {}).get('uplink', 0)) for key in incoming)
        down = sum(int(inbound.get(key, {}).get('downlink', 0)) for key in incoming)
        now = time.monotonic()
        upload_rate = download_rate = 0
        if self.last:
            elapsed = max(.1, now - self.last[0])
            upload_rate = max(0, round((up - self.last[1]) / elapsed))
            download_rate = max(0, round((down - self.last[2]) / elapsed))
        self.last = (now, up, down)
        direct = stats.get('outbound', {}).get('yukiwire-direct', {})
        self.last_direct = sum(int(direct.get(direction, 0)) for direction in ('uplink', 'downlink'))
        return {'upload_bytes': up, 'download_bytes': down, 'upload_bps': upload_rate, 'download_bps': download_rate,
                'direct_bytes': self.last_direct,
                }
