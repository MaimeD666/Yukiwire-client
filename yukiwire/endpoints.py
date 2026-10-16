"""Per-session loopback endpoints. Credentials are ephemeral and never persisted."""
import base64
from dataclasses import dataclass, field
import secrets
import socket

# Compatibility defaults for standalone config builders and test tools only.
SOCKS_PORT, HTTP_PORT = 11808, 11809
STATS_PORT, PROBE_PORT = 11811, 11812
_socket = socket.socket


@dataclass(frozen=True)
class Endpoint:
    port: int
    username: str = field(default='', repr=False)
    password: str = field(default='', repr=False)

    @property
    def accounts(self):
        return [{'user': self.username, 'pass': self.password}] if self.username else []

    @property
    def headers(self):
        if not self.username:
            return {}
        token = base64.b64encode((self.username + ':' + self.password).encode()).decode('ascii')
        return {'Proxy-Authorization': 'Basic ' + token}

    def inbound(self, tag, protocol='http'):
        settings = {'accounts': self.accounts}
        if protocol == 'socks':
            settings.update(auth='password', udp=False)
        return dict(tag=tag, listen='127.0.0.1', port=self.port, protocol=protocol, settings=settings)


def allocate_endpoints():
    """Ask Windows for four distinct ports; Xray still fails closed on a bind race."""
    sockets = []
    try:
        result = {}
        for name in ('http', 'socks', 'probe', 'metrics'):
            sock = _socket()
            sockets.append(sock)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind(('127.0.0.1', 0))
            result[name] = Endpoint(sock.getsockname()[1], *(
                ('', '') if name == 'http' else ('yukiwire', secrets.token_urlsafe(32))))
        return result
    finally:
        for sock in sockets:
            sock.close()


def configure_local(config, endpoints, settings):
    config['inbounds'] = []
    if settings['capture'] != 'tun' or settings['tun_system_proxy']:
        config['inbounds'].append(endpoints['http'].inbound('local-http'))
        config['inbounds'].append(endpoints['socks'].inbound('local-socks', 'socks'))
        for inbound in config['inbounds']:
            inbound['sniffing'] = {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': True}
    return config
