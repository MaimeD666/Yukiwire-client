"""Normal-user recovery marker; WFP ownership remains in the protected helper."""
import copy
import ipaddress
from urllib.parse import urlsplit

from .dns_config import add_bootstrap, configure_tun_dns, system_servers
from .paths import STATE
from .storage import SecureFile


def enabled(settings):
    return settings.get('kill_switch', False) and settings.get('capture') in ('system', 'tun')


def configure(config, settings, direct_servers=None):
    if not enabled(settings):
        return config
    if settings['preset'] == 'original':
        raise ValueError('Для защиты от утечек выберите управляемый режим маршрутизации Yukiwire.')
    config = copy.deepcopy(config)
    servers = ([value.strip() for value in settings['dns_direct'].split(',')] if settings['dns_direct'] != 'system'
               else system_servers() if direct_servers is None else direct_servers)
    if settings['capture'] != 'tun':
        primary = next(o for o in config['outbounds'] if o['protocol'] not in ('freedom', 'blackhole', 'dns', 'loopback'))
        configure_tun_dns(config, dict(settings, dns='doh'), primary['tag'], servers)
        config['routing']['rules'].insert(0, {'type': 'field', 'inboundTag': ['yukiwire-dns'], 'outboundTag': primary['tag']})
    hostnames = set()
    for outbound in config['outbounds']:
        protocol = outbound['protocol']
        if protocol in ('blackhole', 'dns', 'loopback'):
            continue
        if protocol == 'freedom':
            outbound.setdefault('settings', {})['domainStrategy'] = 'UseIP'
            continue
        values = outbound.get('settings', {})
        if protocol == 'wireguard':
            for peer in values.get('peers', []):
                try:
                    ipaddress.ip_address(urlsplit('//' + peer['endpoint']).hostname)
                except (ValueError, KeyError, TypeError):
                    raise ValueError('Для WireGuard с защитой от утечек укажите IP-адрес endpoint вместо имени.') from None
            continue
        # Resolve from inside Xray. Windows' shared DNS client is deliberately
        # not exempted from the WFP block when a protected connection is down.
        outbound.setdefault('streamSettings', {}).setdefault('sockopt', {})['domainStrategy'] = 'UseIP'
        servers_to_resolve = values.get('vnext', []) + values.get('servers', [])
        if isinstance(values.get('address'), str):
            servers_to_resolve.append(values)
        for server in servers_to_resolve:
            address = server.get('address')
            if not address:
                continue
            try:
                ipaddress.ip_address(address)
            except ValueError:
                hostnames.add(address)
    for hostname in sorted(hostnames):
        add_bootstrap(config, hostname, servers)
    return config


class KillSwitch:
    def __init__(self, file=None):
        self.file = file or SecureFile(STATE / 'kill-switch.dpapi')

    @property
    def active(self):
        # Conservative even if an arm attempt failed: recovery must confirm that
        # no persistent filter is left before the UI says protection is released.
        return self.file.path.exists()

    def check_start(self, settings, broker):
        if self.active:
            record = self.file.read()
            if not enabled(settings) or record.get('helper_id') != broker.identity:
                raise ValueError('Сначала отключите защиту предыдущего подключения кнопкой «Снять блокировку» или восстановите сеть.')

    def arm(self, broker, serial):
        self.check_start({'kill_switch': True, 'capture': 'tun'}, broker)
        self.file.write({'helper_id': broker.identity})
        if not broker.request('arm', serial=serial):
            raise ValueError('Не удалось включить защиту от утечек. Требуется восстановление сети.')

    def release(self, broker=None):
        if not self.active:
            return
        from .broker import Broker
        identity = self.file.read().get('helper_id')
        if not isinstance(identity, str):
            raise ValueError('Повреждён журнал защиты от утечек. Он сохранён для восстановления.')
        temporary = broker is None or broker.closed.is_set() or broker.identity != identity
        if temporary:
            broker = Broker(component_identity=identity)
        try:
            if not broker.request('release'):
                raise ValueError('Не подтверждено снятие блокировки сети. Журнал сохранён.')
            self.file.path.unlink()
        finally:
            if temporary:
                broker.close()
