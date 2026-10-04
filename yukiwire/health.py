"""Explicit CONNECT tunnel; independent of Windows proxy and environment vars."""
import http.client
import ssl
import time
import re
from concurrent.futures import ThreadPoolExecutor

SITES = ('example.com', 'github.com', 'www.youtube.com', 'chatgpt.com', 'auth.openai.com')


def diagnostic_config(config):
    """Separate probe listener pins checks to the primary outbound, including split routing."""
    primary = next((o for o in config['outbounds'] if o['protocol'] not in ('freedom', 'blackhole', 'dns', 'loopback')), config['outbounds'][0])
    if not primary.get('tag'):
        used = {o.get('tag') for o in config['outbounds']}
        tag = 'yukiwire-check-primary'
        while tag in used:
            tag += '-1'
        primary['tag'] = tag
    config['inbounds'].append({'tag': 'yukiwire-check', 'listen': '127.0.0.1', 'port': 11812, 'protocol': 'http', 'settings': {}})
    config.setdefault('routing', {}).setdefault('rules', []).insert(0, {'type': 'field', 'inboundTag': ['yukiwire-check'], 'outboundTag': primary['tag']})
    return config


def trace_country(data):
    values = dict(line.split('=', 1) for line in data.decode('utf-8', errors='replace').splitlines() if '=' in line)
    country = values.get('loc', '')
    if not re.fullmatch('[A-Z]{2}', country):
        raise ValueError('Источник не вернул страну соединения.')
    return country  # Never retain the trace's IP, user-agent, or full body.


def exit_country(port=11812, host='www.cloudflare.com'):
    connection = http.client.HTTPSConnection('127.0.0.1', port, timeout=10, context=ssl.create_default_context())
    connection.set_tunnel(host, 443)
    try:
        connection.request('GET', '/cdn-cgi/trace', headers={'Host': host, 'User-Agent': 'Yukiwire/0.4', 'Connection': 'close'})
        response = connection.getresponse()
        if response.status != 200:
            return {'country': None, 'http_status': response.status, 'source': host}
        return {'country': trace_country(response.read(8192)), 'source': host}
    except Exception as exc:
        return {'country': None, 'error_type': type(exc).__name__, 'source': host}
    finally:
        connection.close()


def check_exit():
    with ThreadPoolExecutor(max_workers=2) as executor:
        profile = executor.submit(exit_country)
        chatgpt = executor.submit(exit_country, 11809, 'chatgpt.com')
        return {'profile': profile.result(), 'chatgpt_route': chatgpt.result()}


def check_connection():
    with ThreadPoolExecutor(max_workers=2) as executor:
        sites = executor.submit(check_sites)
        country = executor.submit(check_exit)
        return {'results': sites.result(), 'exit': country.result()}


def check_sites(port=11809):
    def check(host):
        try:
            result = probe_https(port=port, host=host, timeout=10)
            status = result['http_status']
            result['transport_ok'] = True
            result['accessible'] = 200 <= status < 400
            result['message'] = ('Отвечает (HTTP %s)' % status if result['accessible'] else
                                 'Сайт ограничил доступ (HTTP %s)' % status if status in (403, 429, 451) else
                                 'Ответ сайта: HTTP %s' % status)
            return result
        except Exception as exc:
            return {'target': host, 'transport_ok': False, 'accessible': False,
                    'message': 'Нет HTTPS-соединения (%s)' % type(exc).__name__}
    with ThreadPoolExecutor(max_workers=3) as executor:
        return list(executor.map(check, SITES))


def probe_https(port=11809, host='example.com', path='/', timeout=15):
    started = time.monotonic()
    connection = http.client.HTTPSConnection('127.0.0.1', port, timeout=timeout,
                                             context=ssl.create_default_context())
    connection.set_tunnel(host, 443)
    try:
        connection.request('GET', path, headers={'Host': host, 'User-Agent': 'Yukiwire/0.4', 'Connection': 'close'})
        response = connection.getresponse()
        response.read(1024)
        return {'http_status': response.status, 'elapsed_ms': round((time.monotonic() - started) * 1000),
                'tls_verified': True, 'target': host, 'proxy_port': port}
    finally:
        connection.close()
