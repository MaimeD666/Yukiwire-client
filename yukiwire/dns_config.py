"""Build ordered DNS policies from the same domain rules as managed routing."""
import ipaddress
from urllib.parse import urlsplit


def validate_resolvers(direct, vpn):
    if not isinstance(direct, str) or not isinstance(vpn, str) or len(direct) > 1024 or len(vpn) > 2048:
        raise ValueError('Некорректные настройки DNS.')
    direct, vpn = direct.strip(), vpn.strip()
    if direct != 'system':
        try:
            servers = [str(ipaddress.ip_address(value.strip())) for value in direct.split(',')]
        except ValueError:
            raise ValueError('Прямой DNS: system или IP-адреса через запятую.') from None
        if not 1 <= len(servers) <= 4 or any(ipaddress.ip_address(value).is_unspecified or value in ('172.29.250.2', '172.29.250.1') for value in servers):
            raise ValueError('Прямой DNS не может указывать на сам Yukiwire TUN.')
        direct = ', '.join(dict.fromkeys(servers))
    url = urlsplit(vpn)
    if (url.scheme != 'https' or not url.hostname or url.username or url.password or url.fragment or
            any(ord(char) < 33 for char in vpn)):
        raise ValueError('DNS через VPN должен быть HTTPS-адресом DoH без логина и пароля.')
    try:
        if url.port is not None and not 0 < url.port < 65536:
            raise ValueError()
    except ValueError:
        raise ValueError('Некорректный порт DoH.') from None
    return direct, vpn


def system_servers():
    """Snapshot before capture; never use localhost after Windows points at TUN."""
    from .windows_snapshot import adapters, routes
    defaults = {entry['index'] for entry in routes() if entry['prefix'] in ('0.0.0.0/0', '::/0')}
    result = []
    for adapter in adapters():
        if not adapter['up'] or adapter['name'].startswith('Yukiwire-') or not defaults.intersection({adapter['index'], adapter['index6']}):
            continue
        for value in adapter['dns']:
            address = ipaddress.ip_address(value)
            if not address.is_unspecified and not address.is_loopback and not address.is_link_local and value not in ('172.29.250.1', '172.29.250.2') and '%' not in value:
                result.append(str(address))
    return list(dict.fromkeys(result))[:4]


def configure_tun_dns(config, settings, primary, direct_servers=None):
    direct, vpn = validate_resolvers(settings.get('dns_direct', 'system'), settings.get('dns_vpn', 'https://1.1.1.1/dns-query'))
    hostname = urlsplit(vpn).hostname
    try:
        ipaddress.ip_address(hostname)
        bootstrap = None
    except ValueError:
        bootstrap = hostname
    use_split = settings.get('dns', 'doh') == 'system'
    if not use_split:
        config['dns'] = {'servers': [vpn], 'tag': 'yukiwire-dns', 'queryStrategy': 'UseIP'}
        if bootstrap:
            add_bootstrap(config, bootstrap, system_servers() if direct_servers is None else direct_servers)
        return
    rules = config['routing']['rules']
    direct_targets = {outbound['tag'] for outbound in config['outbounds'] if outbound.get('protocol') == 'freedom' and outbound.get('tag')}
    blocked_targets = {outbound['tag'] for outbound in config['outbounds'] if outbound.get('protocol') == 'blackhole' and outbound.get('tag')}
    servers = [value.strip() for value in direct.split(',')] if direct != 'system' else (system_servers() if direct_servers is None else direct_servers)
    if not servers:
        raise ValueError('Не удалось определить системный DNS до TUN. Укажите IP прямого DNS или выберите все DNS через VPN.')
    result, hosts = [], {}

    def append_group(domains, direct_route):
        upstreams = servers if direct_route else [vpn]
        for index, address in enumerate(upstreams):
            entry = {'address': address, 'tag': 'yukiwire-dns-direct' if direct_route else 'yukiwire-dns',
                     'finalQuery': index == len(upstreams) - 1}
            if domains:
                entry.update(domains=domains, skipFallback=True)
            result.append(entry)

    for rule in rules:
        if rule.get('inboundTag') or rule.get('process') or not rule.get('domain'):
            continue  # DNS cannot attribute Windows resolver requests to a game process.
        if rule.get('outboundTag') in blocked_targets:
            for domain in rule['domain']:
                hosts[domain] = ['0.0.0.0', '::']
        else:
            append_group(rule['domain'], rule.get('outboundTag') in direct_targets)
    append_group(None, settings.get('preset') == 'selected')
    config['dns'] = {'servers': result, 'hosts': hosts, 'tag': 'yukiwire-dns',
                     'queryStrategy': 'UseIP', 'disableFallbackIfMatch': True}
    if not direct_targets:
        raise ValueError('Для раздельного DNS нужен управляемый прямой маршрут.')
    direct_tag = 'yukiwire-direct' if 'yukiwire-direct' in direct_targets else sorted(direct_targets)[0]
    rules.insert(0, {'type': 'field', 'inboundTag': ['yukiwire-dns-direct'], 'outboundTag': direct_tag})
    if bootstrap:
        add_bootstrap(config, bootstrap, servers)


def add_bootstrap(config, hostname, servers):
    if not servers:
        raise ValueError('Для имени DoH-сервера нужен DNS до подключения TUN. Укажите DoH с IP-адресом.')
    # Only the resolver hostname is resolved before its HTTPS connection exists.
    # An ordinary domain cannot fall back to the physical DNS after a VPN failure.
    group = [{'address': address, 'domains': ['full:' + hostname], 'skipFallback': True,
              'finalQuery': index == len(servers) - 1, 'tag': 'yukiwire-dns-bootstrap'}
             for index, address in enumerate(servers)]
    config['dns']['servers'][0:0] = group
    config['dns']['disableFallbackIfMatch'] = True
    config['routing']['rules'].insert(0, {'type': 'field', 'inboundTag': ['yukiwire-dns-bootstrap'],
                                        'outboundTag': 'yukiwire-direct'})
