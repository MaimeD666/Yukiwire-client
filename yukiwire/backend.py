"""Application service: profiles, routing, guarded capture, telemetry and recovery."""
from collections import deque
import ctypes
from ctypes import wintypes
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time

from .config import build_config
from .geodata import RuleSets
from .health import probe_https, check_connection, diagnostic_config
from .network import NetworkGuard, WinInetProxy, add_tun, conflicts, new_tun, recover_stale, tun_preflight, tun_ready
from .paths import ROOT, STATE, CORE, RUNTIME
from .process import CoreProcess
from .routing import DEFAULTS, apply_routing, explain, normalize_settings
from .storage import ProfileStore, SecureFile, atomic_write
from .telemetry import Telemetry, enable_metrics
from .analytics import Analytics


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

    def start(self, text, settings=None, cancel=None):
        with self.lock:
            if self.core:
                raise ValueError('Сначала отключите текущий профиль.')
            name, config = build_config(text)
            if settings is None:
                settings = dict(DEFAULTS, preset='original' if text.lstrip().startswith('{') else 'ru-direct')
            self.settings = normalize_settings(settings)
            if self.settings['capture'] != 'local':
                collision = conflicts()
                if collision['other_proxy'] or collision['other_vpn']:
                    raise NetworkConflict('Работает другой VPN или системный прокси. Для совместного теста с Nekoray выберите «Локальный прокси».')
            identity = None
            if self.settings['capture'] == 'tun':
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    raise ValueError('Для TUN нужны права администратора у сетевого помощника. Подтвердите запрос Windows при подключении.')
                if not (CORE.parent / 'wintun.dll').is_file():
                    raise ValueError('Нет драйвера wintun.dll. Установите официальный Wintun из инструкции.')
                if self.settings['preset'] == 'original':
                    raise ValueError('Для TUN выберите режим маршрутизации Yukiwire, а не исходный JSON.')
                identity = new_tun()
                tun_preflight()
            config = apply_routing(config, self.settings, RuleSets().tags())
            config = enable_metrics(config)
            config = diagnostic_config(config)
            if identity:
                config = add_tun(config, identity)
            for port in (11808, 11809, 11811, 11812):
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
                        self.guard.arm(self.settings['capture'], pid, identity)
                        if cancel and cancel.is_set():
                            raise ValueError('Подключение отменено.')
                        collision = conflicts()
                        if collision['other_proxy'] or collision['other_vpn']:
                            raise NetworkConflict('Другой VPN появился во время запуска. Сетевые изменения Yukiwire отменены.')
                self.core = CoreProcess(CORE, config, before_resume)
                deadline = time.monotonic() + (20 if identity else 5)
                while time.monotonic() < deadline:
                    if cancel and cancel.is_set():
                        raise ValueError('Подключение отменено.')
                    if self.core.process.poll() is not None:
                        raise ValueError('Ядро завершилось при запуске. Сетевые изменения будут восстановлены.')
                    with socket.socket() as sock:
                        sock.settimeout(.2)
                        if sock.connect_ex(('127.0.0.1', 11809)) == 0:
                            if identity and not tun_ready(identity):
                                time.sleep(.2)
                                continue
                            if self.settings['capture'] != 'local':
                                # Never hand Windows an unverified local proxy endpoint.
                                probe_https(port=11812)
                            if cancel and cancel.is_set():
                                raise ValueError('Подключение отменено.')
                            if self.settings['capture'] != 'local':
                                collision = conflicts()
                                if collision['other_proxy'] or collision['other_vpn']:
                                    raise NetworkConflict('Другой VPN появился во время проверки. Yukiwire отключён.')
                            self.guard.apply_proxy()
                            self.generation += 1
                            self.started_at = time.monotonic()
                            self.telemetry = Telemetry()
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
        return probe_https(port=11812)


class ApplicationService:
    def __init__(self, emit, profiles=None, settings_file=None):
        self.emit = emit
        self.session = Session()
        self.profiles = profiles or ProfileStore()
        self.settings_file = settings_file or SecureFile(STATE / 'settings.dpapi')
        self.settings = dict(DEFAULTS)
        self.commands = queue.Queue()
        self.closing = threading.Event()
        self.stop_requested = threading.Event()
        self.stop_requested.set()
        self.last_profile = None
        self.active_profile_id = None
        self.history = deque(maxlen=100)
        self.restarting = False
        self.probing = False
        self.last_health = 0
        self.connection_since = None
        self.probe_lock = threading.Lock()
        self.healthy = False
        self.failed_checks = 0
        self.sites_lock = threading.Lock()
        self.site_results = None
        self.last_probe_result = None
        self.last_probe_generation = None
        self.last_capture_check = 0
        self.environment = None
        self.environment_lock = threading.Lock()
        self.analytics = None if os.environ.get('YUKIWIRE_TEST_SESSION') == '1' else Analytics()

    def log(self, message, severity='info'):
        entry = {'time': time.strftime('%H:%M:%S'), 'message': message, 'severity': severity}
        self.history.append(entry)
        self.emit('activity', **entry)

    def initialize(self):
        warning = None
        try:
            recovery = recover_stale()
            if recovery.get('conflict'):
                warning = 'Журнал восстановления требует проверки: настройки изменены другим приложением.'
            elif recovery.get('requires_elevation'):
                warning = 'Для восстановления TUN нажмите «Проверить восстановление» в настройках и подтвердите запрос Windows.'
        except Exception:
            warning = 'Не удалось восстановить предыдущую сеть. Журнал сохранён; проверьте восстановление в настройках.'
        try:
            self.settings = normalize_settings(self.settings_file.read(DEFAULTS))
            library = self.profiles.public()
        except Exception:
            warning = 'Сохранённые данные или восстановление сети недоступны. Импорт без сохранения остаётся доступен.'
            library = {'profiles': [], 'selected': None}
        environment = self._refresh_environment(publish=False)
        try:
            rules = RuleSets().metadata()
        except Exception:
            rules = {'version': 'Списки повреждены', 'source': 'Недоступно', 'custom': False}
            warning = 'Не удалось прочитать версию списков. Обновите их в настройках.'
        self.emit('ready', settings=self.settings, **library, environment=environment,
                   rules=rules, warning=warning)
        self._analytics('initialize')
        threading.Thread(target=self._worker, daemon=True).start()
        threading.Thread(target=self._monitor, daemon=True).start()
        threading.Thread(target=self._environment_monitor, daemon=True).start()

    def _refresh_environment(self, publish=True, manual=False):
        # Serialize scans and publication so a slower old scan cannot replace a newer one.
        with self.environment_lock:
            try:
                environment = dict(conflicts(), admin=bool(ctypes.windll.shell32.IsUserAnAdmin()),
                                   wintun_present=(CORE.parent / 'wintun.dll').is_file())
            except Exception:
                environment = {'other_proxy': False, 'other_vpn': False, 'check_failed': True}
            changed = environment != self.environment
            self.environment = environment
            if publish and (changed or manual) and not self.closing.is_set():
                self.emit('environment', environment=environment, silent=not manual)
            return dict(environment)

    def _environment_monitor(self):
        # Independent of commands and telemetry: also refresh while idle or reconnecting.
        while not self.closing.wait(5):
            try:
                self._refresh_environment()
            except (BrokenPipeError, OSError):
                return  # The owner closed its output pipe; normal EOF/close handles cleanup.

    def submit(self, request):
        if self.closing.is_set():
            return
        if request.get('action') == 'start':
            self.stop_requested.clear()
        if request.get('action') in ('stop', 'quit'):
            self.stop_requested.set()
            core = self.session.core
            if core and core.process.poll() is None:
                try:
                    core.process.terminate()
                except OSError:
                    pass
        if request.get('action') == 'quit':
            self.close()
            return
        self.commands.put(request)

    def _worker(self):
        while not self.closing.is_set():
            try:
                request = self.commands.get(timeout=.2)
            except queue.Empty:
                continue
            try:
                self._command(request)
            except Exception as exc:
                if request.get('action') == 'start' and self.stop_requested.is_set() and not self.session.core:
                    self.emit('stopped')
                    continue
                message = str(exc) if isinstance(exc, ValueError) else 'Операция не выполнена (%s). Настройки не будут сброшены.' % type(exc).__name__
                self.log(message, 'error')
                self.emit('error', message=message, operation=request.get('action'))

    def _command(self, request):
        action = request.get('action')
        if action == 'start':
            if self.stop_requested.is_set() or self.closing.is_set():
                self.emit('stopped')
                return
            if self.session.core:
                raise ValueError('Сначала отключите текущий профиль.')
            text = request.get('profile')
            self.active_profile_id = None
            if not text:
                profile = self.profiles.get(request.get('profile_id'))
                text = profile['text']
                self.profiles.select(profile['id'])
                self.active_profile_id = profile['id']
            settings = normalize_settings(request.get('settings', self.settings))
            self.last_profile = text
            self.healthy = False
            self.failed_checks = 0
            self.site_results = None
            self.last_probe_result = None
            self.last_probe_generation = None
            self.session.failure_count = self.session.reconnect_count = 0
            self.session.completed_upload = self.session.completed_download = self.session.completed_direct = 0
            self.connection_since = time.monotonic()
            self.emit('starting')
            result = self.session.start(text, settings, self.stop_requested)
            if self.stop_requested.is_set():
                self.session.stop()
                self.emit('stopped')
                return
            self._analytics('begin', result['capture'], settings['preset'])
            self.log('Ядро запущено; ожидается проверка HTTPS.')
            self.emit('started', pid=result['pid'], capture=result['capture'], reconnected=False)
            self._probe(manual=False)
            self._command({'action': 'check_sites'})
        elif action == 'stop':
            try:
                self.session.stop()
            finally:
                self.healthy = False
                if not self.session.core:
                    self._analytics('finish', self._session_totals())
                    self.last_profile = None
                    self.active_profile_id = None
                    self.emit('stopped')
            self.log('Соединение закрыто; собственные сетевые изменения восстановлены.')
        elif action == '_capture_conflict':
            if request.get('generation') != self.session.generation:
                return
            self.stop_requested.set()
            self.restarting = False
            try:
                self._command({'action': 'stop'})
            finally:
                self.log('Изменился системный прокси или запущен другой VPN. Yukiwire отключён; автоматический захват сети остановлен.', 'warning')
        elif action == '_core_exited':
            if request.get('generation') != self.session.generation or self.stop_requested.is_set():
                return
            core = self.session.core
            if not core or core.process.poll() is None:
                return
            self.stop_requested.set()
            self.emit('core_exited', code=core.process.returncode, diagnostics=core.diagnostics())
            self._command({'action': 'stop'})
        elif action == 'probe':
            self._probe(manual=True)
        elif action == 'refresh_environment':
            self._refresh_environment(manual=True)
        elif action == 'get_analytics':
            self._analytics('overview')
        elif action == 'get_state':
            settings = self.session.settings if self.session.core else self.settings
            self.emit('ready', settings=settings, **self.profiles.public(), environment=self._refresh_environment(publish=False),
                      rules=RuleSets().metadata(), warning=None)
            self._analytics('overview')
            core = self.session.core
            if core and core.process.poll() is None:
                # Publish only public metadata; a temporary config never crosses back to the renderer.
                transient = None
                if not self.active_profile_id:
                    raw = self.last_profile or ''
                    transient = {'name': 'Временный профиль', 'protocol': 'JSON Xray' if raw.lstrip().startswith('{') else raw.split('://')[0]}
                self.emit('started', pid=core.process.pid, capture=self.session.settings['capture'],
                          reconnected=True, transient=transient)
                if self.healthy and self.last_probe_result and self.last_probe_generation == self.session.generation:
                    self.emit('probe_result', **self.last_probe_result)
                if self.site_results and self.site_results['generation'] == self.session.generation:
                    self.emit('sites_result', results=self.site_results['results'], exit=self.site_results['exit'])
            for entry in self.history:
                self.emit('activity', **entry)
        elif action == 'open_browser':
            if not self.session.core or self.session.core.process.poll() is not None:
                raise ValueError('Сначала подключите профиль Yukiwire.')
            # The service may be elevated for TUN. Only the normal-user host launches browsers.
            self.emit('browser_requested')
        elif action == 'check_sites':
            if not self.session.core:
                raise ValueError('Сначала подключитесь.')
            if not self.sites_lock.acquire(blocking=False):
                return
            generation = self.session.generation
            self.emit('sites_checking')
            def check():
                try:
                    report = check_connection()
                    results = report['results']
                    if generation == self.session.generation and not self.stop_requested.is_set():
                        self.site_results = {'time': int(time.time()), 'generation': generation, **report}
                        self._analytics('update', country=report.get('exit', {}).get('profile', {}).get('country'))
                        self.emit('sites_result', **report)
                        for result in results:
                            self.log(result['target'] + ': ' + result['message'], 'info' if result['accessible'] else 'warning')
                finally:
                    self.sites_lock.release()
            threading.Thread(target=check, daemon=True).start()
        elif action == '_restart':
            if request.get('generation') != self.session.generation:
                self.restarting = False
                return
            try:
                attempt = 0
                self.session.reconnect_count += 1
                while not self.stop_requested.is_set() and not self.closing.is_set():
                    attempt += 1
                    self.emit('reconnecting', attempt=attempt)
                    try:
                        self.session.stop()
                    except Exception:
                        self.stop_requested.set()
                        self.last_profile = None
                        self.healthy = False
                        if not self.session.core:
                            self.emit('stopped')
                        raise
                    if self.stop_requested.wait(min(30, 2 ** min(attempt - 1, 5))):
                        break
                    try:
                        result = self.session.start(self.last_profile, self.session.settings, self.stop_requested)
                        if self.stop_requested.is_set():
                            self.session.stop()
                            break
                        self.emit('started', pid=result['pid'], capture=result['capture'], reconnected=True)
                        self.log('Ядро перезапущено. Проверяем связь.')
                        self._probe(manual=False)
                        break
                    except NetworkConflict as exc:
                        self.stop_requested.set()
                        self.last_profile = None
                        self.healthy = False
                        self.emit('stopped')
                        self.log(str(exc) + ' Автоподключение остановлено.', 'warning')
                        break
                    except Exception:
                        self.log('Перезапуск пока не удался. Следующая попытка с задержкой.', 'warning')
                if self.stop_requested.is_set():
                    self.session.stop()
            finally:
                self.restarting = False
                if self.stop_requested.is_set():
                    self._analytics('finish', self._session_totals())
        elif action == 'save_profile':
            text = request.get('profile', '')
            name, config = build_config(text)
            validate_config(config)
            identity = self.profiles.save(text, request.get('name') or name, 'JSON Xray' if text.lstrip().startswith('{') else config['outbounds'][0]['protocol'], request.get('profile_id'))
            self.emit('profiles', **self.profiles.public())
            self.emit('saved', profile_id=identity)
            self.log('Профиль сохранён с защитой Windows DPAPI.')
        elif action == 'delete_profile':
            if self.session.core:
                raise ValueError('Сначала отключитесь перед удалением профиля.')
            self.profiles.remove(request.get('profile_id'))
            self.emit('profiles', **self.profiles.public())
        elif action == 'get_profile':
            if self.session.core:
                raise ValueError('Отключитесь перед редактированием профиля.')
            self.emit('profile_detail', **self.profiles.get(request.get('profile_id')))
        elif action == 'save_settings':
            if self.session.core:
                raise ValueError('Отключитесь перед сохранением маршрутизации. Работающее подключение не будет изменено.')
            settings = normalize_settings(request.get('settings', {}))
            self.settings_file.write(settings)
            self.settings = settings
            self.emit('settings', settings=settings)
            self.log('Настройки сохранены. Они применятся при следующем подключении.')
        elif action == 'explain':
            self.emit('route_explanation', **explain(request.get('target', ''), request.get('settings', self.settings), RuleSets().membership))
        elif action in ('update_rules', 'rollback_rules'):
            if self.session.core:
                raise ValueError('Отключитесь перед заменой списков. Текущее подключение сохранено.')
            self.emit('rules_updating')
            def validate(tags):
                _, candidate = build_config('vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls')
                for preset in ('ru-direct', 'selected'):
                    validate_config(apply_routing(candidate, dict(DEFAULTS, preset=preset), tags))
            manager = RuleSets()
            # If another VPN owns the system proxy, use it explicitly for this optional download.
            proxy = WinInetProxy().read()
            download_proxy = None
            if proxy['flags'] & 2:
                import re
                match = re.search(r'(?:http=)?127\.0\.0\.1:(\d+)', proxy['server'])
                download_proxy = int(match.group(1)) if match else None
            metadata = manager.update(validate, download_proxy) if action == 'update_rules' else manager.rollback(validate)
            self.emit('rules_updated', rules=metadata)
            self.log('Версия списков проверена и активирована.')
        elif action == 'recover_network':
            if self.session.core:
                raise ValueError('Сначала отключитесь.')
            result = self.session.guard.recover() if self.session.guard.kind else recover_stale()
            if result.get('requires_elevation'):
                self.emit('recovery_elevation_required')
                return
            if result.get('restored'):
                self.session.guard.kind = None
            self.emit('recovered', **result)
        elif action == 'export_diagnostics':
            # Whitelist only; no server addresses, profile names, domains/rules or raw logs.
            report = {'version': '0.4', 'active': bool(self.session.core), 'capture': self.session.settings['capture'],
                      'preset': self.session.settings['preset'], 'https_verified': self.healthy,
                      'failed_checks': self.session.failure_count, 'reconnects': self.session.reconnect_count,
                      'network_journal_present': self.session.guard.journal.path.exists(),
                      'last_site_check': self.site_results,
                      'core_diagnostics': self.session.core.diagnostics() if self.session.core else []}
            target = RUNTIME / 'diagnostics.json'
            atomic_write(target, json.dumps(report, ensure_ascii=False, indent=2).encode())
            self.emit('diagnostics_exported', path=str(target))
        else:
            raise ValueError('Неизвестная команда.')

    def _probe(self, manual):
        generation = self.session.generation
        if not self.session.core:
            raise ValueError('Сначала подключитесь.')
        if not self.probe_lock.acquire(blocking=False):
            return
        self.probing = True
        self.last_health = time.monotonic()
        if manual:
            self.emit('probing')
        def check():
            try:
                result = self.session.probe()
                if self.session.generation != generation or self.stop_requested.is_set():
                    return
                self.healthy = True  # Even a website's 403 proves verified TLS transport.
                self.failed_checks = 0
                self.last_probe_result = result
                self.last_probe_generation = generation
                self.emit('probe_result', **result)
                self._analytics('update', latency=result['elapsed_ms'])
                self.log('HTTPS-соединение проверено; сертификат действителен.')
            except Exception as exc:
                if self.session.generation != generation or self.stop_requested.is_set():
                    return
                self.healthy = False
                self.failed_checks += 1
                self.session.failure_count += 1
                message = 'HTTPS не прошёл (%s).' % type(exc).__name__
                diagnostics = self.session.core.diagnostics() if self.session.core else []
                self.emit('error', message=message, operation='probe', diagnostics=diagnostics)
                self.log(message, 'warning')
            finally:
                self.probing = False
                self.probe_lock.release()
                if self.session.generation != generation and self.session.core and not self.stop_requested.is_set() and not self.closing.is_set():
                    self._probe(manual=False)
        threading.Thread(target=check, daemon=True).start()

    def _monitor(self):
        while not self.closing.wait(2):
            core = self.session.core
            generation = self.session.generation
            if not core:
                continue
            if core.process.poll() is not None:
                self.healthy = False
                if self.session.settings['auto_reconnect'] and not self.stop_requested.is_set():
                    if not self.restarting:
                        self.restarting = True
                        self.commands.put({'action': '_restart', 'generation': generation})
                else:
                    self.commands.put({'action': '_core_exited', 'generation': generation})
                continue
            if self.session.started_at and time.monotonic() - self.last_capture_check >= 5:
                self.last_capture_check = time.monotonic()
                try:
                    self._check_capture(generation)
                except Exception:
                    # An unverifiable system state is not permission to take it over.
                    if self.session.settings['capture'] != 'local':
                        self.commands.put({'action': '_capture_conflict', 'generation': generation})
            try:
                stats = self.session.telemetry.sample()
                stats['upload_bytes'] += self.session.completed_upload
                stats['download_bytes'] += self.session.completed_download
                stats['direct_bytes'] += self.session.completed_direct
                stats.update({'uptime': int(time.monotonic() - self.connection_since) if self.connection_since else 0,
                              'failures': self.session.failure_count, 'reconnects': self.session.reconnect_count})
                if self.session.core is core:
                    self.emit('telemetry', **stats)
                    self._analytics('update', stats)
            except Exception:
                pass
            if not self.stop_requested.is_set() and time.monotonic() - self.last_health > 30:
                if self.session.settings['auto_reconnect'] and self.failed_checks >= 3 and not self.restarting:
                    self.restarting = True
                    self.commands.put({'action': '_restart', 'generation': generation})
                elif not self.restarting:
                    self._probe(manual=False)

    def _check_capture(self, generation):
        mode = self.session.settings['capture']
        if mode == 'local' or self.stop_requested.is_set():
            return
        collision = conflicts()
        if mode == 'system':
            record = self.session.guard.journal.read()
            collision['other_proxy'] = (collision['other_proxy'] or not record or
                                        record.get('lease_id') != self.session.guard.lease_id or
                                        WinInetProxy().read() != record.get('desired'))
        if collision['other_proxy'] or collision['other_vpn']:
            self.commands.put({'action': '_capture_conflict', 'generation': generation})
            return
        if mode == 'tun':
            record = self.session.guard.journal.read()
            if not record or record.get('lease_id') != self.session.guard.lease_id:
                self.commands.put({'action': '_capture_conflict', 'generation': generation})
            elif not tun_ready(record) and not self.restarting:
                self.healthy = False
                if self.session.settings['auto_reconnect']:
                    self.restarting = True
                    self.commands.put({'action': '_restart', 'generation': generation})
                else:
                    self.commands.put({'action': '_capture_conflict', 'generation': generation})

    def close(self):
        self.stop_requested.set()
        self.closing.set()
        core = self.session.core
        if core and core.process.poll() is None:
            try:
                core.process.terminate()
            except OSError:
                pass
        try:
            self.session.stop()
        finally:
            self._analytics('finish', self._session_totals())

    def _session_totals(self):
        return {'uptime': int(time.monotonic() - self.connection_since) if self.connection_since else 0,
                'download_bytes': self.session.completed_download, 'upload_bytes': self.session.completed_upload,
                'direct_bytes': self.session.completed_direct, 'failures': self.session.failure_count,
                'reconnects': self.session.reconnect_count}

    def _analytics(self, operation, *args, **kwargs):
        if self.analytics is None:
            return
        try:
            result = getattr(self.analytics, operation)(*args, **kwargs)
            if operation in ('initialize', 'overview', 'finish'):
                self.emit('analytics', **(result or self.analytics.overview()))
        except Exception:
            # History persistence must never stop networking or recovery.
            pass


def main():
    sys.stdin.reconfigure(encoding='utf-8')
    sys.stdout.reconfigure(encoding='utf-8', line_buffering=True)
    output_lock = threading.Lock()
    def emit(event, **values):
        with output_lock:
            print(json.dumps(dict(event=event, **values), ensure_ascii=False), flush=True)
    service = ApplicationService(emit)
    try:
        service.initialize()
        for line in sys.stdin:
            if len(line) > 4 * 1024 * 1024:
                emit('error', message='Слишком большой запрос.', operation='input')
                continue
            try:
                request = json.loads(line)
                if not isinstance(request, dict):
                    raise ValueError()
                service.submit(request)
                if request.get('action') == 'quit':
                    break
            except (ValueError, TypeError):
                emit('error', message='Некорректный запрос.', operation='input')
    except BrokenPipeError:
        pass
    finally:
        service.close()


if __name__ == '__main__':
    main()
