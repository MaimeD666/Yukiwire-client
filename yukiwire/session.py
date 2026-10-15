"""Connection ownership: core, network capture, endpoints and protected recovery."""
import json
import socket
import subprocess
import threading
import time

from .config import build_config
from .geodata import RuleSets
from .health import probe_https, diagnostic_config
from .network import NetworkGuard, add_tun, conflicts, new_tun, tun_preflight, tun_ready
from .paths import CORE
from .process import CoreProcess
from .routing import DEFAULTS, apply_routing, normalize_settings
from .telemetry import Telemetry, enable_metrics
from .endpoints import allocate_endpoints, configure_local
from .broker import Broker, ElevatedCore
from . import killswitch


class NetworkConflict(ValueError):
    """Another application owns capture; do not repeatedly try to take it back."""


def validate_config(config):
    if not CORE.is_file():
        raise ValueError('Нет ядра Xray. Запустите установку ядра.')
    validation = subprocess.run([str(CORE), 'run', '-test', '-format', 'json', '-c', 'stdin:'], cwd=CORE.parent,
                                input=json.dumps(config).encode(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
    if validation.returncode:
        raise ValueError('Xray отклонил конфигурацию. Проверьте профиль, режим маршрутизации и наличие списков.')


class Session:
    def __init__(self):
        self.core = None
        self.guard = NetworkGuard()
        self.telemetry = Telemetry()
        self.generation = 0
        self.started_at = None
        self.settings = dict(DEFAULTS)
        self.failure_count = 0
        self.reconnect_count = 0
        self.lock = threading.RLock()
        self.completed_upload = self.completed_download = self.completed_direct = 0
        self.endpoints = {}
        self.listener_ports = []
        self.broker = None
        self.diagnostic_sink = None
        self.protection = killswitch.KillSwitch()

    def network_broker(self, cancel=None):
        if self.broker is None or self.broker.closed.is_set():
            self.broker = Broker(cancel)
            self.broker.diagnostic_sink = self.diagnostic_sink
        return self.broker

    def start(self, text, settings=None, cancel=None):
        with self.lock:
            if self.core:
                raise ValueError('Сначала отключите текущий профиль.')
            name, config = build_config(text)
            if settings is None:
                settings = dict(DEFAULTS, preset='original' if text.lstrip().startswith('{') else 'ru-direct')
            self.settings = normalize_settings(settings)
            if self.protection.active and not killswitch.enabled(self.settings):
                raise ValueError('Защита предыдущего подключения удерживает блокировку. Сначала снимите её кнопкой отключения или восстановите сеть.')
            self.endpoints = allocate_endpoints()
            if self.settings['capture'] != 'local':
                collision = conflicts()
                if collision['other_proxy'] or collision['other_vpn']:
                    raise NetworkConflict('Работает другой VPN или системный прокси. Для совместного теста с Nekoray выберите «Локальный прокси».')
            identity = None
            if self.settings['capture'] == 'tun':
                if not (CORE.parent / 'wintun.dll').is_file():
                    raise ValueError('Нет драйвера wintun.dll. Установите официальный Wintun из инструкции.')
                if self.settings['preset'] == 'original':
                    raise ValueError('Для TUN выберите режим маршрутизации Yukiwire, а не исходный JSON.')
                identity = new_tun()
                tun_preflight()
            config = apply_routing(config, self.settings, RuleSets().tags())
            config = configure_local(config, self.endpoints, self.settings)
            config = enable_metrics(config, self.endpoints['metrics'])
            config = diagnostic_config(config, self.endpoints['probe'])
            if identity:
                config = add_tun(config, identity, self.settings)
            config = killswitch.configure(config, self.settings)
            self.listener_ports = [inbound['port'] for inbound in config['inbounds'] if 'port' in inbound]
            for port in self.listener_ports:
                with socket.socket() as sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                    try:
                        sock.bind(('127.0.0.1', port))
                    except OSError:
                        raise ValueError('Порт %s занят другим экземпляром. Чужие процессы не будут завершены.' % port) from None
            try:
                validate_config(config)
                if cancel and cancel.is_set():
                    raise ValueError('Подключение отменено.')
                config['log'] = {'loglevel': 'info'}
                before_resume = None
                if self.settings['capture'] != 'local':
                    def before_resume(pid):
                        if cancel and cancel.is_set():
                            raise ValueError('Подключение отменено.')
                        self.guard.arm(self.settings['capture'], pid, identity,
                                       system_proxy=self.settings['capture'] == 'tun' and self.settings['tun_system_proxy'],
                                       proxy_port=self.endpoints['http'].port)
                        if cancel and cancel.is_set():
                            raise ValueError('Подключение отменено.')
                        collision = conflicts()
                        if collision['other_proxy'] or collision['other_vpn']:
                            raise NetworkConflict('Другой VPN появился во время запуска. Сетевые изменения Yukiwire отменены.')
                protected = killswitch.enabled(self.settings)
                if identity or protected:
                    broker = self.network_broker(cancel)
                    self.protection.check_start(self.settings, broker)
                    self.core = ElevatedCore(broker, config, identity, before_resume,
                                             protection=self.protection if protected else None)
                else:
                    self.core = CoreProcess(CORE, config, before_resume, on_event=self.diagnostic_sink)
                deadline = time.monotonic() + (20 if identity else 5)
                while time.monotonic() < deadline:
                    if cancel and cancel.is_set():
                        raise ValueError('Подключение отменено.')
                    if self.core.process.poll() is not None:
                        raise ValueError('Ядро завершилось при запуске. Сетевые изменения будут восстановлены.')
                    with socket.socket() as sock:
                        sock.settimeout(.2)
                        if sock.connect_ex(('127.0.0.1', self.endpoints['probe'].port)) == 0:
                            if identity and not tun_ready(identity):
                                time.sleep(.2)
                                continue
                            if identity and protected:
                                self.core.permit_tun()
                            if self.settings['capture'] != 'local':
                                # Never hand Windows an unverified local proxy endpoint.
                                probe_https(port=self.endpoints['probe'].port, headers=self.endpoints['probe'].headers)
                            if cancel and cancel.is_set():
                                raise ValueError('Подключение отменено.')
                            if self.settings['capture'] != 'local':
                                collision = conflicts()
                                if collision['other_proxy'] or collision['other_vpn']:
                                    raise NetworkConflict('Другой VPN появился во время проверки. Yukiwire отключён.')
                            self.guard.apply_proxy()
                            self.generation += 1
                            self.started_at = time.monotonic()
                            self.telemetry = Telemetry(self.endpoints['metrics'])
                            return {'pid': self.core.process.pid, 'name': name, 'capture': self.settings['capture']}
                    time.sleep(.1)
                raise ValueError('Ядро не открыло локальный порт вовремя.')
            except Exception:
                self.stop()
                raise

    def stop(self):
        with self.lock:
            self.generation += 1
            core = self.core
            try:
                if core:
                    core.close()
            finally:
                if core and core.process.poll() is None:
                    # Keep ownership and recovery armed until termination is confirmed.
                    raise RuntimeError('Не удалось подтвердить остановку ядра. Защита восстановления сохранена.')
                if core:
                    if self.telemetry.last:
                        self.completed_upload += self.telemetry.last[1]
                        self.completed_download += self.telemetry.last[2]
                        self.completed_direct += self.telemetry.last_direct
                self.core = None
                self.started_at = None
                if self.guard.kind:
                    result = self.guard.recover()
                    if result.get('conflict'):
                        raise ValueError('Прокси изменён другим приложением. Yukiwire сохранил новые настройки и журнал для проверки.')
                    if not result.get('restored'):
                        raise ValueError('Восстановление сети не завершено. Журнал сохранён; проверьте восстановление в настройках.')
                    self.guard.kind = None

    def probe(self):
        if not self.core or self.core.process.poll() is not None:
            raise ValueError('Ядро не запущено.')
        endpoint = self.endpoints['probe']
        return probe_https(port=endpoint.port, headers=endpoint.headers)

    def public_endpoints(self):
        if not self.core or not self.endpoints or (self.settings['capture'] == 'tun' and not self.settings['tun_system_proxy']):
            return {}
        return {key: dict(port=self.endpoints[key].port, username=self.endpoints[key].username,
                          password=self.endpoints[key].password) for key in ('http', 'socks')}

    def own_proxy(self):
        if not self.core or not self.endpoints or self.settings['capture'] == 'local':
            return None
        return '127.0.0.1:%d' % self.endpoints['http'].port
