import json
import uuid
import base64
from urllib.parse import urlsplit, parse_qs, unquote, quote, urlencode


def decode_base64(value):
    try:
        return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)).decode('utf-8')
    except Exception:
        raise ValueError('Некорректная base64-ссылка.') from None


def other_link(text, socks_port, http_port):
    if text.startswith('vmess://'):
        try:
            payload = json.loads(decode_base64(text[8:]))
            supported = {'v', 'ps', 'add', 'port', 'id', 'aid', 'scy', 'net', 'type', 'host', 'path', 'tls', 'sni', 'alpn', 'fp'}
            if not isinstance(payload, dict) or set(payload) - supported:
                raise ValueError('VMess содержит неподдерживаемые поля.')
            if payload.get('type', 'none') not in ('', 'none'):
                raise ValueError('VMess header type пока не поддерживается; используйте JSON Xray.')
            identifier = str(uuid.UUID(payload['id']))
            address, port = str(payload['add']), int(payload['port'])
            if not 0 < port < 65536:
                raise ValueError('Неверный порт VMess.')
            query = {'type': payload.get('net', 'tcp'), 'security': 'tls' if payload.get('tls') == 'tls' else 'none'}
            for name in ('host', 'path', 'sni', 'alpn', 'fp'):
                if payload.get(name):
                    query[name] = str(payload[name])
            if query['type'] == 'grpc':
                query['serviceName'] = query.pop('path', '')
            host = '[' + address + ']' if ':' in address else address
            name, config = build_config('vless://' + identifier + '@' + host + ':' + str(port) + '?' + urlencode(query) + '#' + quote(str(payload.get('ps', 'VMess'))), socks_port, http_port)
            config['outbounds'][0]['protocol'] = 'vmess'
            config['outbounds'][0]['settings']['vnext'][0]['users'] = [{'id': identifier, 'alterId': int(payload.get('aid') or 0), 'security': payload.get('scy') or 'auto'}]
            return name, config
        except (KeyError, TypeError, json.JSONDecodeError):
            raise ValueError('Некорректный профиль VMess.') from None
    if text.startswith('trojan://'):
        uri = urlsplit(text)
        if not uri.hostname or not uri.port or '@' not in uri.netloc:
            raise ValueError('В Trojan нужны пароль, адрес и порт.')
        password = unquote(uri.netloc.rsplit('@', 1)[0])
        query = {k: v[0] for k, v in parse_qs(uri.query, keep_blank_values=True).items()}
        query.setdefault('security', 'tls')
        host = '[' + uri.hostname + ']' if ':' in uri.hostname else uri.hostname
        name, config = build_config('vless://00000000-0000-4000-8000-000000000001@' + host + ':' + str(uri.port) + '?' + urlencode(query) + '#' + uri.fragment, socks_port, http_port)
        config['outbounds'][0].update({'protocol': 'trojan', 'settings': {'servers': [{'address': uri.hostname, 'port': uri.port, 'password': password}]}})
        return name, config
    if text.startswith('ss://'):
        body = text[5:]
        if '@' not in body.split('#', 1)[0]:
            encoded, _, fragment = body.partition('#')
            text = 'ss://' + decode_base64(encoded) + ('#' + fragment if fragment else '')
        uri = urlsplit(text)
        if uri.query:
            raise ValueError('Плагины Shadowsocks в ссылках пока не поддерживаются; используйте JSON.')
        if not uri.hostname or not uri.port or '@' not in uri.netloc:
            raise ValueError('Некорректный адрес Shadowsocks.')
        credentials = unquote(uri.netloc.rsplit('@', 1)[0])
        if ':' not in credentials:
            credentials = decode_base64(credentials)
        method, separator, password = credentials.partition(':')
        if not separator or not method or not password:
            raise ValueError('В Shadowsocks нужны метод шифрования и пароль.')
        config = {'outbounds': [{'tag': 'proxy', 'protocol': 'shadowsocks', 'settings': {'servers': [{'address': uri.hostname, 'port': uri.port, 'method': method, 'password': password}]}}, {'tag': 'direct', 'protocol': 'freedom'}]}
        _, result = build_config(json.dumps(config), socks_port, http_port)
        return unquote(uri.fragment) or 'Shadowsocks', result
    raise ValueError('Поддерживаются VLESS, VMess, Trojan, Shadowsocks и JSON Xray.')


def build_config(text, socks_port=11808, http_port=11809):
    text = text.strip()
    if text.startswith('{'):
        original = json.loads(text)
        if not isinstance(original.get('outbounds'), list) or not original['outbounds']:
            raise ValueError('Нужен JSON Xray с непустым массивом outbounds.')
        # Never execute user-provided listeners, APIs or file logging.
        config = {k: original[k] for k in ('outbounds', 'routing', 'dns', 'policy') if k in original}
        name = 'JSON Xray'
    else:
        uri = urlsplit(text)
        if uri.scheme != 'vless':
            return other_link(text, socks_port, http_port)
        identity = str(uuid.UUID(uri.username or ''))
        if not uri.hostname or not uri.port:
            raise ValueError('В ссылке должны быть адрес и порт сервера.')
        q = {k: v[0] for k, v in parse_qs(uri.query, keep_blank_values=True).items()}
        supported = {'encryption', 'security', 'sni', 'fp', 'alpn', 'type', 'path', 'mode', 'flow', 'pbk', 'sid', 'spx', 'host', 'serviceName', 'extra'}
        unknown = set(q) - supported
        if unknown:
            raise ValueError('Параметры пока не поддерживаются: ' + ', '.join(sorted(unknown)))
        network = q.get('type', 'tcp')
        if q.get('extra') and network != 'xhttp':
            raise ValueError('Параметр extra поддерживается только для XHTTP.')
        if network not in ('tcp', 'raw', 'xhttp', 'ws', 'grpc'):
            raise ValueError('Транспорт пока не поддерживается: ' + network)
        security = q.get('security', 'none')
        if security not in ('none', 'tls', 'reality'):
            raise ValueError('Неизвестный режим безопасности.')
        stream = {'network': network, 'security': security}
        if security == 'tls':
            stream['tlsSettings'] = {'serverName': q.get('sni', uri.hostname), 'fingerprint': q.get('fp', 'chrome'), 'allowInsecure': False}
            if q.get('alpn'):
                stream['tlsSettings']['alpn'] = q['alpn'].split(',')
        if security == 'reality':
            stream['realitySettings'] = {'serverName': q.get('sni', ''), 'fingerprint': q.get('fp', 'chrome'), 'publicKey': q.get('pbk', ''), 'shortId': q.get('sid', ''), 'spiderX': q.get('spx', '/')}
        if network == 'xhttp':
            stream['xhttpSettings'] = {'path': q.get('path', '/'), 'mode': q.get('mode', 'auto')}
            if q.get('host'):
                stream['xhttpSettings']['host'] = q['host']
            if q.get('extra'):
                try:
                    extra = json.loads(q['extra'])
                    if not isinstance(extra, dict):
                        raise ValueError()
                    stream['xhttpSettings']['extra'] = extra
                except ValueError:
                    raise ValueError('Параметр extra должен содержать JSON-объект XHTTP.') from None
        if network == 'ws':
            stream['wsSettings'] = {'path': q.get('path', '/')}
            if q.get('host'):
                stream['wsSettings']['headers'] = {'Host': q['host']}
        if network == 'grpc':
            stream['grpcSettings'] = {'serviceName': q.get('serviceName', '')}
        user = {'id': identity, 'encryption': q.get('encryption', 'none')}
        if q.get('flow'):
            user['flow'] = q['flow']
        config = {'outbounds': [{'tag': 'proxy', 'protocol': 'vless', 'settings': {'vnext': [{'address': uri.hostname, 'port': uri.port, 'users': [user]}]}, 'streamSettings': stream}, {'tag': 'direct', 'protocol': 'freedom'}]}
        name = unquote(uri.fragment) or 'VLESS'
    config['log'] = {'loglevel': 'warning'}
    safe_outbounds = {'vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'freedom', 'blackhole', 'dns', 'loopback'}
    for outbound in config['outbounds']:
        if not isinstance(outbound, dict) or outbound.get('protocol') not in safe_outbounds:
            raise ValueError('JSON содержит неподдерживаемый исходящий протокол. Системные интерфейсы в технической версии запрещены.')
    config['inbounds'] = [
        {'tag': 'local-socks', 'listen': '127.0.0.1', 'port': socks_port, 'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}},
        {'tag': 'local-http', 'listen': '127.0.0.1', 'port': http_port, 'protocol': 'http', 'settings': {}}
    ]
    return name, config
