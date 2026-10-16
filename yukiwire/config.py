import json
import uuid
import base64
import re
from urllib.parse import urlsplit, parse_qs, unquote


LINK_PARAMETERS = {'encryption', 'security', 'sni', 'peer', 'fp', 'alpn', 'type', 'path', 'mode',
                   'flow', 'pbk', 'sid', 'spx', 'host', 'serviceName', 'extra', 'headerType',
                   'allowInsecure', 'pqv', 'seed'}
HYSTERIA_PARAMETERS = {'sni', 'insecure', 'obfs', 'obfs-password', 'pinSHA256', 'alpn', 'ech'}


def link_query(uri):
    values = parse_qs(uri.query, keep_blank_values=True)
    if any(len(value) != 1 for value in values.values()):
        raise ValueError('Параметры ссылки не должны повторяться.')
    return {key: value[0] for key, value in values.items()}


def profile_warnings(text):
    """Do not echo unknown keys/values: either can contain private profile data."""
    uri = urlsplit(text.strip()) if not text.lstrip().startswith('{') else None
    if uri and uri.scheme in ('vless', 'trojan'):
        unknown = set(link_query(uri)) - LINK_PARAMETERS
        if unknown:
            return ['Пропущено неизвестных параметров ссылки: %s. Проверьте транспорт перед подключением.' % len(unknown)]
    if uri and uri.scheme in ('hy2', 'hysteria2') and set(link_query(uri)) - HYSTERIA_PARAMETERS:
        return ['Неизвестные дополнительные параметры Hysteria2 пропущены. Проверьте профиль.']
    if uri and uri.scheme == 'vmess':
        payload = json.loads(decode_base64(text.strip()[8:]))
        known = {'v', 'ps', 'add', 'port', 'id', 'aid', 'scy', 'net', 'type', 'host', 'path', 'tls', 'sni', 'alpn', 'fp'}
        if isinstance(payload, dict) and set(payload) - known:
            return ['Неизвестные дополнительные поля VMess пропущены. Проверьте транспорт перед подключением.']
    return []


def stream_settings(q, hostname, default_security='none'):
    network = q.get('type', 'tcp')
    if q.get('extra') and network != 'xhttp':
        raise ValueError('Параметр extra поддерживается только для XHTTP.')
    if network in ('h2', 'http'):
        raise ValueError('H2-транспорт удалён из этой версии Xray. Нужен профиль XHTTP от поставщика сервера.')
    if network not in ('tcp', 'raw', 'xhttp', 'ws', 'grpc', 'httpupgrade', 'kcp'):
        raise ValueError('Транспорт ссылки пока не поддерживается; используйте совместимый JSON Xray.')
    if q.get('headerType', 'none') not in ('', 'none'):
        raise ValueError('Этот headerType не поддерживается; используйте JSON Xray.')
    if q.get('seed'):
        raise ValueError('Эта версия Xray больше не применяет KCP seed. Требуется совместимый профиль сервера.')
    if q.get('allowInsecure', 'false').lower() not in ('', 'false', '0'):
        raise ValueError('Ссылка требует отключить проверку TLS. Исправьте сертификат или параметры сервера.')
    security = q.get('security', default_security)
    if security not in ('none', 'tls', 'reality'):
        raise ValueError('Неизвестный режим безопасности.')
    stream = {'network': network, 'security': security}
    if security == 'tls':
        stream['tlsSettings'] = {'serverName': q.get('sni') or q.get('peer') or hostname,
                                 'fingerprint': q.get('fp') or 'chrome', 'allowInsecure': False}
        if q.get('alpn'):
            stream['tlsSettings']['alpn'] = q['alpn'].split(',')
    if security == 'reality':
        if not q.get('pbk'):
            raise ValueError('Для Reality в ссылке обязателен ключ pbk.')
        stream['realitySettings'] = {'serverName': q.get('sni') or q.get('peer', ''),
                                     'fingerprint': q.get('fp') or 'chrome', 'publicKey': q['pbk'],
                                     'shortId': q.get('sid', ''), 'spiderX': q.get('spx', '/')}
        if q.get('pqv'):
            stream['realitySettings']['mldsa65Verify'] = q['pqv']
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
    if network == 'httpupgrade':
        stream['httpupgradeSettings'] = {'path': q.get('path', '/')}
        if q.get('host'):
            stream['httpupgradeSettings']['host'] = q['host']
    if network == 'grpc':
        stream['grpcSettings'] = {'serviceName': q.get('serviceName', '')}
    if network == 'kcp':
        stream['kcpSettings'] = {}
    return stream


def finish_link(name, outbound, socks_port, http_port):
    _, config = build_config(json.dumps({'outbounds': [outbound, {'tag': 'direct', 'protocol': 'freedom'}]}), socks_port, http_port)
    return name, config


def decode_base64(value):
    try:
        return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)).decode('utf-8')
    except Exception:
        raise ValueError('Некорректная base64-ссылка.') from None


def other_link(text, socks_port, http_port):
    if text.startswith(('hy2://', 'hysteria2://')):
        uri = urlsplit(text)
        if not uri.hostname:
            raise ValueError('В Hysteria2 нужен адрес сервера.')
        query = link_query(uri)
        if query.get('insecure', '0').lower() not in ('', '0', 'false'):
            raise ValueError('Hysteria2: отключение проверки TLS запрещено. Исправьте сертификат или укажите его SHA256.')
        tls = {'serverName': query.get('sni') or uri.hostname, 'allowInsecure': False}
        if query.get('alpn'):
            tls['alpn'] = query['alpn'].split(',')
        if query.get('pinSHA256'):
            digest = query['pinSHA256'].replace(':', '')
            if not re.fullmatch('[a-fA-F0-9]{64}', digest):
                raise ValueError('Hysteria2: неверный SHA256 сертификата.')
            tls['pinnedPeerCertSha256'] = digest
        if query.get('ech'):
            tls['echConfigList'] = query['ech']
        stream = {'network': 'hysteria', 'security': 'tls', 'tlsSettings': tls,
                  'hysteriaSettings': {'version': 2, 'auth': unquote(uri.netloc.rsplit('@', 1)[0]) if '@' in uri.netloc else ''}}
        obfs = query.get('obfs', '')
        if obfs:
            if obfs != 'salamander' or not query.get('obfs-password'):
                raise ValueError('Поддерживается obfs=salamander с непустым obfs-password.')
            stream['finalmask'] = {'udp': [{'type': 'salamander', 'settings': {'password': query['obfs-password']}}]}
        outbound = {'tag': 'proxy', 'protocol': 'hysteria', 'settings': {'version': 2, 'address': uri.hostname, 'port': uri.port or 443},
                    'streamSettings': stream}
        return finish_link(unquote(uri.fragment) or 'Hysteria2', outbound, socks_port, http_port)
    if text.startswith('vmess://'):
        try:
            payload = json.loads(decode_base64(text[8:]))
            if not isinstance(payload, dict):
                raise ValueError('Некорректный профиль VMess.')
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
            outbound = {'tag': 'proxy', 'protocol': 'vmess', 'settings': {'vnext': [{'address': address, 'port': port,
                        'users': [{'id': identifier, 'alterId': int(payload.get('aid') or 0), 'security': payload.get('scy') or 'auto'}]}]},
                        'streamSettings': stream_settings(query, address)}
            return finish_link(str(payload.get('ps') or 'VMess'), outbound, socks_port, http_port)
        except (KeyError, TypeError, json.JSONDecodeError):
            raise ValueError('Некорректный профиль VMess.') from None
    if text.startswith('trojan://'):
        uri = urlsplit(text)
        if not uri.hostname or not uri.port or '@' not in uri.netloc:
            raise ValueError('В Trojan нужны пароль, адрес и порт.')
        password = unquote(uri.netloc.rsplit('@', 1)[0])
        if not password:
            raise ValueError('В Trojan нужен непустой пароль.')
        query = link_query(uri)
        outbound = {'tag': 'proxy', 'protocol': 'trojan',
                    'settings': {'servers': [{'address': uri.hostname, 'port': uri.port, 'password': password}]},
                    'streamSettings': stream_settings(query, uri.hostname, 'tls')}
        return finish_link(unquote(uri.fragment) or 'Trojan', outbound, socks_port, http_port)
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
    raise ValueError('Поддерживаются VLESS, VMess, Trojan, Shadowsocks, Hysteria2 и JSON Xray.')


def build_config(text, socks_port=11808, http_port=11809):
    if not isinstance(text, str) or len(text) > 4 * 1024 * 1024:
        raise ValueError('Профиль должен быть текстом размером не более 4 МиБ.')
    text = text.strip()
    if text.startswith('{'):
        original = json.loads(text)
        if not isinstance(original, dict) or not isinstance(original.get('outbounds'), list) or not original['outbounds']:
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
        q = link_query(uri)
        stream = stream_settings(q, uri.hostname)
        user = {'id': identity, 'encryption': q.get('encryption', 'none')}
        if q.get('flow'):
            user['flow'] = q['flow']
        config = {'outbounds': [{'tag': 'proxy', 'protocol': 'vless', 'settings': {'vnext': [{'address': uri.hostname, 'port': uri.port, 'users': [user]}]}, 'streamSettings': stream}, {'tag': 'direct', 'protocol': 'freedom'}]}
        name = unquote(uri.fragment) or 'VLESS'
    config['log'] = {'loglevel': 'warning'}
    safe_outbounds = {'vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria', 'wireguard', 'socks', 'http', 'freedom', 'blackhole', 'dns', 'loopback'}
    for outbound in config['outbounds']:
        if not isinstance(outbound, dict) or outbound.get('protocol') not in safe_outbounds:
            raise ValueError('JSON содержит неподдерживаемый исходящий протокол. Системные интерфейсы в технической версии запрещены.')
        if outbound['protocol'] == 'wireguard':
            settings = outbound.setdefault('settings', {})
            if not isinstance(settings, dict) or 'kernelMode' in settings or settings.get('noKernelTun', True) is not True:
                raise ValueError('WireGuard поддерживается только в userspace, без системного интерфейса.')
            settings['noKernelTun'] = True
    config['inbounds'] = [
        {'tag': 'local-socks', 'listen': '127.0.0.1', 'port': socks_port, 'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}},
        {'tag': 'local-http', 'listen': '127.0.0.1', 'port': http_port, 'protocol': 'http', 'settings': {}}
    ]
    return name, config
