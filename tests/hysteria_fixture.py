"""Synthetic Hysteria peer (loopback by default); keys live only in memory."""
from contextlib import contextmanager
import hashlib
import json
import secrets
import socket
import ssl
import subprocess
import time

from yukiwire.process import CoreProcess


@contextmanager
def hysteria_peer(executable, obfs=False, outbound=None, host='127.0.0.1'):
    result = subprocess.run([str(executable), 'tls', 'cert', '-json', '-domain=hy2.test'],
                            capture_output=True, check=True, timeout=10,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    certificate = json.loads(result.stdout)
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert('\n'.join(certificate['certificate']))).hexdigest()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket() as tcp:
        udp.bind((host, 0))
        tcp.bind(('127.0.0.1', 0))
        port, ready = udp.getsockname()[1], tcp.getsockname()[1]
    password, obfs_password = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    stream = {'network': 'hysteria', 'security': 'tls',
              'tlsSettings': {'alpn': ['h3'], 'certificates': [certificate]},
              'hysteriaSettings': {'version': 2, 'auth': 'user:' + password}}
    suffix = ''
    if obfs:
        stream['finalmask'] = {'udp': [{'type': 'salamander', 'settings': {'password': obfs_password}}]}
        suffix = '&obfs=salamander&obfs-password=' + obfs_password
    config = {'log': {'loglevel': 'warning'},
              'dns': {'servers': ['1.1.1.1'], 'queryStrategy': 'UseIPv4'},
              'inbounds': [{'listen': host, 'port': port, 'protocol': 'hysteria',
                            'settings': {'version': 2}, 'streamSettings': stream},
                           {'listen': '127.0.0.1', 'port': ready, 'protocol': 'http', 'settings': {}}],
              # Xray servers deny private destinations by default; permit only our test loopback.
              'outbounds': [outbound or {'protocol': 'freedom', 'settings': {
                  'finalRules': [{'action': 'allow', 'network': 'tcp,udp', 'ip': ['127.0.0.1/32']}]}}]}
    core = CoreProcess(executable, config)
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.create_connection(('127.0.0.1', ready), timeout=.2):
                    break
            except OSError:
                if core.process.poll() is not None or time.monotonic() >= deadline:
                    raise AssertionError('Synthetic Hysteria peer failed to start')
                time.sleep(.03)
        yield f'hy2://user%3A{password}@{host}:{port}/?sni=hy2.test&insecure=1&pinSHA256={pin}{suffix}'
    finally:
        core.close()
