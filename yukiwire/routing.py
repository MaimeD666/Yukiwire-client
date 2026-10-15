"""Deterministic first-match routing, shared by Xray config and UI explanation."""
import copy
import ipaddress
import ntpath
import re
from urllib.parse import urlsplit

PRIVATE = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10']
DEFAULTS = {'preset': 'ru-direct', 'direct': '', 'proxy': '', 'block': '', 'ru_ip': False, 'dns': 'system', 'auto_reconnect': True, 'capture': 'local',
            'game_mode': False, 'game_processes': 'dota2.exe', 'tun_system_proxy': False, 'reconnect_on_change': False,
            'browser_home': 'about:blank', 'dns_direct': 'system', 'dns_vpn': 'https://1.1.1.1/dns-query', 'debug_logging': False, 'kill_switch': False}
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


def parse_game_processes(text):
    """Accept exact Windows executable names/paths, never folder-wide matches."""
    if not isinstance(text, str) or len(text) > 16384:
        raise ValueError('Слишком большой список игр.')
    processes = []
    for value in text.splitlines():
        value = value.strip()
        if not value:
            continue
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        value = value.replace('\\', '/')
        drive, tail = ntpath.splitdrive(value)
        if (len(value) > 1024 or any(ord(c) < 32 or c in '<>"|?*' for c in value)
                or ':' in tail or not value.lower().endswith('.exe') or ntpath.basename(value).lower() == '.exe'
                or ('/' in value and not (drive and tail.startswith('/')))
                or (drive and not tail.startswith('/'))
                or (drive and not (re.fullmatch(r'[A-Za-z]:', drive) or drive.startswith('//')))
                or any(part in ('.', '..') for part in value.split('/'))):
            raise ValueError('Укажите имя игры с .exe или полный путь к её .exe, по одному в строке. Сохраните регистр букв.')
        if value not in processes:
            processes.append(value)
        if len(processes) > 100:
            raise ValueError('Можно выбрать не больше 100 процессов игр.')
    return processes


def browser_home(value):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 32 for c in value):
        raise ValueError('Некорректный адрес стартовой страницы.')
    value = value.strip() or 'about:blank'
    if value != 'about:blank':
        url = urlsplit(value)
        if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password:
            raise ValueError('Стартовая страница: HTTP(S)-адрес или about:blank.')
    return value


def normalize_settings(settings):
    result = dict(DEFAULTS)
    result.update({k: v for k, v in settings.items() if k in DEFAULTS})
    result['browser_home'] = browser_home(result['browser_home'])
    from .dns_config import validate_resolvers
    result['dns_direct'], result['dns_vpn'] = validate_resolvers(result['dns_direct'], result['dns_vpn'])
    if result['preset'] not in PRESETS or result['dns'] not in ('system', 'doh') or result['capture'] not in ('local', 'system', 'tun'):
        raise ValueError('Неизвестный режим настроек.')
    for key in ('direct', 'proxy', 'block'):
        if not isinstance(result[key], str) or len(result[key]) > 65536:
            raise ValueError('Слишком много правил.')
        parse_rules(result[key])
    for key in ('ru_ip', 'auto_reconnect', 'game_mode', 'tun_system_proxy', 'reconnect_on_change', 'debug_logging', 'kill_switch'):
        if type(result[key]) is not bool:
            raise ValueError('Некорректное значение переключателя.')
    processes = parse_game_processes(result['game_processes'])
    result['game_processes'] = '\n'.join(processes)
    if result['game_mode'] and not processes:
        raise ValueError('Выберите хотя бы одну игру или отключите игровой режим.')
    return result


def connection_settings(settings):
    """Only values that affect traffic; UI and recovery preferences apply immediately."""
    result = normalize_settings(settings)
    for key in ('auto_reconnect', 'reconnect_on_change', 'browser_home', 'debug_logging'):
        result.pop(key)
    if result['preset'] != 'ru-direct':
        result['ru_ip'] = False
    if result['preset'] == 'original':
        result.update(direct='', proxy='', block='', game_mode=False)
    if not result['game_mode']:
        result['game_processes'] = ''
    if result['capture'] != 'tun':
        result['tun_system_proxy'] = False
        result['dns_direct'] = 'system'
    if result['capture'] == 'local':
        result['kill_switch'] = False
    if result['dns'] == 'doh':
        result['dns_direct'] = 'system'
    elif result['capture'] != 'tun' and not result['kill_switch']:
        result['dns_vpn'] = DEFAULTS['dns_vpn']
    return result


def build_rules(settings, tags, proxy_tag, direct_tag, block_tag):
    rules = []
    for setting, target in [('block', block_tag), ('proxy', proxy_tag), ('direct', direct_tag)]:
        if setting == 'proxy' and settings.get('game_mode'):
            rules.append({'type': 'field', 'process': parse_game_processes(settings['game_processes']),
                          'inboundTag': ['local-socks', 'local-http', 'yukiwire-tun'],
                          'outboundTag': direct_tag})
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
        config['routing'] = {'domainStrategy': 'IPIfNonMatch' if settings['preset'] == 'ru-direct' and settings['ru_ip'] else 'AsIs',
                             'rules': build_rules(settings, tags, proxy_tag, 'yukiwire-direct', 'yukiwire-block')}
    if settings['dns'] == 'doh':
        config['dns'] = {'servers': [settings['dns_vpn']], 'queryStrategy': 'UseIP', 'tag': 'yukiwire-dns'}
        primary = next((o for o in config['outbounds'] if o['protocol'] not in ('freedom', 'blackhole', 'dns', 'loopback')), config['outbounds'][0])
        if not primary.get('tag'):
            raise ValueError('Для DoH назначьте тег главному outbound в исходном JSON.')
        routing = config.setdefault('routing', {'rules': []})
        routing.setdefault('rules', []).insert(0, {'type': 'field', 'inboundTag': ['yukiwire-dns'], 'outboundTag': primary['tag']})
    for inbound in config['inbounds']:
        inbound['sniffing'] = {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': True}
    return config


def explain(value, settings, matcher=None, process=''):
    settings = normalize_settings(settings)
    processes = parse_game_processes(process)
    if len(processes) > 1:
        raise ValueError('Укажите один процесс игры.')
    process = processes[0] if processes else ''
    result = _explain(value, settings, matcher, process)
    if settings['game_mode'] and settings['preset'] != 'original' and not process and result['route'] != 'Блокировать':
        result['reason'] += ' Для выбранной игры действует прямой маршрут; укажите её процесс для проверки.'
        result['definitive'] = False
    return result


def _explain(value, settings, matcher, process):
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
        if key == 'proxy' and settings['game_mode'] and process:
            games = parse_game_processes(settings['game_processes'])
            if any(process == game or ('/' not in game and ntpath.basename(process) == game) for game in games):
                return {'route': 'Напрямую', 'reason': 'Игровой режим: выбранный процесс игры', 'definitive': True}
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
