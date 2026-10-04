"""Deterministic first-match routing, shared by Xray config and UI explanation."""
import copy
import ipaddress
import re
from urllib.parse import urlsplit

PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10']
DEFAULTS = {'preset': 'ru-direct', 'direct': '', 'proxy': '', 'block': '', 'ru_ip': False, 'dns': 'system', 'auto_reconnect': True, 'capture': 'local'}
PRESETS = {'all', 'ru-direct', 'selected', 'original'}


def parse_rules(text):
    domains, addresses = [], []
    for value in re.split(r'[\s,;]+', text.strip()):
        if not value:
            continue
        if len(value) > 253:
            raise ValueError('Слишком длинное правило маршрутизации.')
        try:
            addresses.append(str(ipaddress.ip_network(value, strict=False)))
            continue
        except ValueError:
            pass
        if value.startswith(('http://', 'https://')):
            value = urlsplit(value).hostname or ''
        value = value.lower().removeprefix('*.').rstrip('.')
        # Do not accidentally accept a typo in a CIDR as a domain.
        if '/' in value or ':' in value:
            raise ValueError('Введите домен без пути либо IP/подсеть (CIDR).')
        try:
            value = value.encode('idna').decode('ascii')
        except UnicodeError:
            raise ValueError('Некорректный домен.') from None
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value) or '..' in value:
            raise ValueError('Некорректный домен в правилах.')
        for label in value.split('.'):
            if len(label) > 63 or label.startswith('-') or label.endswith('-'):
                raise ValueError('Некорректный домен в правилах.')
        domains.append(value)
    return list(dict.fromkeys(domains)), list(dict.fromkeys(addresses))


def normalize_settings(settings):
    result = dict(DEFAULTS)
    result.update({k: v for k, v in settings.items() if k in DEFAULTS})
    if result['preset'] not in PRESETS or result['dns'] not in ('system', 'doh') or result['capture'] not in ('local', 'system', 'tun'):
        raise ValueError('Неизвестный режим настроек.')
    for key in ('direct', 'proxy', 'block'):
        if not isinstance(result[key], str) or len(result[key]) > 65536:
            raise ValueError('Слишком много правил.')
        parse_rules(result[key])
    for key in ('ru_ip', 'auto_reconnect'):
        if type(result[key]) is not bool:
            raise ValueError('Некорректное значение переключателя.')
    return result


def build_rules(settings, tags, proxy_tag, direct_tag, block_tag):
    rules = []
    for setting, target in [('block', block_tag), ('proxy', proxy_tag), ('direct', direct_tag)]:
        domains, addresses = parse_rules(settings[setting])
        if domains:
            rules.append({'type': 'field', 'domain': ['domain:' + d for d in domains], 'outboundTag': target})
        if addresses:
            rules.append({'type': 'field', 'ip': addresses, 'outboundTag': target})
    if settings['preset'] in ('ru-direct', 'selected'):
        if tags.get('ru-blocked'):
            rules.append({'type': 'field', 'domain': [tags['ru-blocked']], 'outboundTag': proxy_tag})
        elif settings['preset'] == 'selected':
            # User-managed selected routing is still valid when no lists are installed.
            if not settings['proxy'].strip():
                raise ValueError('Для выбранного VPN добавьте домены/IP в «Через VPN» или обновите списки РФ.')
    rules.extend([
        {'type': 'field', 'domain': ['full:localhost', 'domain:local', 'domain:lan'], 'outboundTag': direct_tag},
        {'type': 'field', 'ip': PRIVATE, 'outboundTag': direct_tag}
    ])
    if settings['preset'] == 'ru-direct':
        if settings['ru_ip'] and not tags.get('geoip-ru'):
            raise ValueError('В активных списках нет IP-категории RU. Отключите российские IP или смените списки.')
        domains = ['domain:ru', 'domain:su', 'domain:xn--p1ai']
        if tags.get('category-ru'):
            domains.append(tags['category-ru'])
        if tags.get('ru-available-only-inside'):
            domains.append(tags['ru-available-only-inside'])
        rules.append({'type': 'field', 'domain': domains, 'outboundTag': direct_tag})
        if settings['ru_ip'] and tags.get('geoip-ru'):
            rules.append({'type': 'field', 'ip': [tags['geoip-ru']], 'outboundTag': direct_tag})
    fallback = direct_tag if settings['preset'] == 'selected' else proxy_tag
    rules.append({'type': 'field', 'network': 'tcp,udp', 'outboundTag': fallback})
    return rules


def apply_routing(config, settings, tags=None):
    config = copy.deepcopy(config)
    settings = normalize_settings(settings)
    tags = tags or {}
    if settings['preset'] != 'original':
        outbounds = config['outbounds']
        primary = next((o for o in outbounds if o['protocol'] not in ('freedom', 'blackhole', 'dns', 'loopback')), None)
        if primary is None:
            primary = outbounds[0]
        used = {o.get('tag') for o in outbounds}
        if not primary.get('tag'):
            index = 0
            while 'yukiwire-proxy-%s' % index in used:
                index += 1
            primary['tag'] = 'yukiwire-proxy-%s' % index
        proxy_tag = primary['tag']
        for name in ('yukiwire-direct', 'yukiwire-block'):
            if name in used:
                raise ValueError('JSON использует зарезервированный тег ' + name)
        outbounds.extend([{'tag': 'yukiwire-direct', 'protocol': 'freedom', 'settings': {}}, {'tag': 'yukiwire-block', 'protocol': 'blackhole', 'settings': {}}])
        config['routing'] = {'domainStrategy': 'IPIfNonMatch' if settings['ru_ip'] else 'AsIs',
                             'rules': build_rules(settings, tags, proxy_tag, 'yukiwire-direct', 'yukiwire-block')}
    if settings['dns'] == 'doh':
        config['dns'] = {'servers': ['https://1.1.1.1/dns-query'], 'queryStrategy': 'UseIP', 'tag': 'yukiwire-dns'}
        primary = next((o for o in config['outbounds'] if o['protocol'] not in ('freedom', 'blackhole', 'dns', 'loopback')), config['outbounds'][0])
        if not primary.get('tag'):
            raise ValueError('Для DoH назначьте тег главному outbound в исходном JSON.')
        routing = config.setdefault('routing', {'rules': []})
        routing.setdefault('rules', []).insert(0, {'type': 'field', 'inboundTag': ['yukiwire-dns'], 'outboundTag': primary['tag']})
    for inbound in config['inbounds']:
        inbound['sniffing'] = {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': True}
    return config


def explain(value, settings, matcher=None):
    settings = normalize_settings(settings)
    value = value.strip()
    if not value:
        raise ValueError('Введите домен или IP.')
    if value.startswith(('http://', 'https://')):
        value = urlsplit(value).hostname or ''
    try:
        address = ipaddress.ip_address(value)
        host = None
    except ValueError:
        address = None
        hosts, ips = parse_rules(value)
        if len(hosts) != 1 or ips:
            raise ValueError('Введите один домен или IP.')
        host = hosts[0]
    if settings['preset'] == 'original':
        return {'route': 'По JSON', 'reason': 'Исходные правила профиля', 'definitive': False}
    for key, target in [('block', 'Блокировать'), ('proxy', 'Через VPN'), ('direct', 'Напрямую')]:
        domains, addresses = parse_rules(settings[key])
        if host and any(host == domain or host.endswith('.' + domain) for domain in domains):
            return {'route': target, 'reason': 'Ваше правило: ' + key, 'definitive': True}
        if address and any(address in ipaddress.ip_network(cidr) for cidr in addresses if ipaddress.ip_network(cidr).version == address.version):
            return {'route': target, 'reason': 'Ваше правило IP/подсети', 'definitive': True}
    membership = matcher(host, address) if matcher and settings['preset'] != 'original' else {}
    if settings['preset'] in ('ru-direct', 'selected') and membership.get('blocked'):
        return {'route': 'Через VPN', 'reason': 'Список заблокированных доменов РФ', 'definitive': False}
    if address and any(address in ipaddress.ip_network(cidr) for cidr in PRIVATE if ipaddress.ip_network(cidr).version == address.version):
        return {'route': 'Напрямую', 'reason': 'Локальная сеть', 'definitive': True}
    if host and (host == 'localhost' or host.endswith(('.local', '.lan'))):
        return {'route': 'Напрямую', 'reason': 'Локальное имя', 'definitive': True}
    if settings['preset'] == 'ru-direct' and membership.get('domestic'):
        return {'route': 'Напрямую', 'reason': 'Домен найден в установленном списке РФ', 'definitive': False}
    if settings['preset'] == 'ru-direct' and settings['ru_ip'] and membership.get('ru_ip'):
        return {'route': 'Напрямую', 'reason': 'IP найден в установленном geoip:ru', 'definitive': True}
    if settings['preset'] == 'ru-direct' and host and (host.endswith(('.ru', '.su', '.xn--p1ai')) or host in ('ru', 'su', 'xn--p1ai')):
        return {'route': 'Напрямую по зоне РФ', 'reason': 'Если домен не входит в список заблокированных. Списки проверяет ядро.', 'definitive': False}
    return {'route': 'Напрямую' if settings['preset'] == 'selected' else 'Через VPN',
            'reason': 'Базовый маршрут. Совпадение с geosite/geoip проверяет ядро.', 'definitive': False}
