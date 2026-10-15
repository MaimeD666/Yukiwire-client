"""Application service: profiles, routing, guarded capture, telemetry and recovery."""
from collections import deque
from functools import wraps
import ctypes
import json
import os
import queue
import sys
import threading
import time

from .config import build_config, profile_warnings
from .geodata import RuleSets
from .health import probe_https, check_connection, diagnostic_config
from .network import WinInetProxy, add_tun, conflicts, new_tun, recover_stale, tun_ready
from .paths import ROOT, STATE, CORE, RUNTIME
from .routing import DEFAULTS, apply_routing, connection_settings, explain, normalize_settings
from .storage import ProfileStore, SecureFile, atomic_write
from .telemetry import enable_metrics
from .analytics import Analytics
from .updates import latest_release
from .version import VERSION, USER_AGENT
from .broker import Broker
from .session import Session, NetworkConflict, validate_config
from . import subscriptions
from .diagnostics import DebugTrace
from . import killswitch


def serialized(method):
    """Serialize service transitions; cancellation signals remain lock-free."""
    @wraps(method)
    def locked(self, *args, **kwargs):
        with self.state_lock:
            return method(self, *args, **kwargs)
    return locked


class ApplicationService:
    def __init__(self, emit, profiles=None, settings_file=None):
        self.state_lock = threading.RLock()
        self._emit_target = emit
        self.trace = DebugTrace()
        self.session = Session()
        self.session.diagnostic_sink = self.trace.record
        self.profiles = profiles or ProfileStore()
        self.settings_file = settings_file or SecureFile(STATE / 'settings.dpapi')
        self.settings = dict(DEFAULTS)
        self.commands = queue.Queue()
        self.closing = threading.Event()
        self.stop_requested = threading.Event()
        self.stop_requested.set()
        self.input_lock = threading.Lock()
        self.pending_starts = []
        self.last_profile = None
        self.active_profile_id = None
        self.history = deque(maxlen=100)
        self.restarting = False
        self.pending_rules = False
        self.subscription_busy = False
        self.profile_check_busy = False
        self.profile_latencies = {}
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
        self.environment = None
        self.environment_lock = threading.Lock()
        self.analytics = None if os.environ.get('YUKIWIRE_TEST_SESSION') == '1' else Analytics()

    @serialized
    def log(self, message, severity='info'):
        entry = {'time': time.strftime('%H:%M:%S'), 'message': message, 'severity': severity}
        self.history.append(entry)
        self.emit('activity', **entry)

    def emit(self, event, **values):
        if event in ('ready', 'starting', 'started', 'stopped', 'error', 'recovered', 'reconnecting'):
            values['network_blocked'] = self.session.protection.active
        context = dict(capture=self.session.settings['capture'], preset=self.session.settings['preset'])
        context.update(values)
        self.trace.record(event, **context)
        self._emit_target(event, **values)

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
            self.trace.enabled = self.settings['debug_logging']
            library = self.profiles.public()
        except Exception:
            warning = 'Защищённые данные недоступны: возможен перенос с другого ПК/учётной записи или повреждение файла. Исходные данные сохранены. Для переноса нужен экспорт профилей на исходном ПК; импорт без сохранения доступен.'
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
                environment = dict(conflicts(own_proxy=self.session.own_proxy()), admin=bool(ctypes.windll.shell32.IsUserAnAdmin()),
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
                generation = self.session.generation
                environment = self._refresh_environment()
                if self.session.core:
                    self._check_capture(generation, environment)
            except (BrokenPipeError, OSError):
                return  # The owner closed its output pipe; normal EOF/close handles cleanup.

    def submit(self, request):
        if self.closing.is_set():
            return
        with self.input_lock:
            if request.get('action') == 'start':
                cancel = threading.Event()
                self.pending_starts.append(cancel)
                request = dict(request, _cancel_event=cancel)
            if request.get('action') in ('stop', 'quit'):
                self.stop_requested.set()
                for cancel in self.pending_starts:
                    cancel.set()
        if request.get('action') in ('stop', 'quit'):
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

    _handlers = {
        'start': '_handle_start',
        'stop': '_handle_stop',
        '_capture_conflict': '_handle_capture_conflict',
        '_core_exited': '_handle_core_exited',
        'probe': '_handle_probe',
        'refresh_environment': '_handle_refresh_environment',
        'get_analytics': '_handle_get_analytics',
        'check_updates': '_handle_check_updates',
        'update_subscription': '_handle_update_subscription',
        'remove_subscription': '_handle_remove_subscription',
        'check_profiles': '_handle_check_profiles',
        'get_state': '_handle_get_state',
        'open_browser': '_handle_open_browser',
        'check_sites': '_handle_check_sites',
        '_restart': '_handle_restart',
        'save_profile': '_handle_save_profile',
        'delete_profile': '_handle_delete_profile',
        'export_profiles': '_handle_export_profiles',
        'import_profiles': '_handle_import_profiles',
        'get_profile': '_handle_get_profile',
        'save_settings': '_handle_save_settings',
        'explain': '_handle_explain',
        'update_rules': '_handle_update_rules',
        'rollback_rules': '_handle_update_rules',
        'recover_network': '_handle_recover_network',
        'export_diagnostics': '_handle_export_diagnostics',
        'clear_diagnostics': '_handle_clear_diagnostics',
    }

    @serialized
    def _command(self, request):
        method = self._handlers.get(request.get('action'))
        if method is None:
            raise ValueError('Неизвестная команда.')
        return getattr(self, method)(request)

    def _handle_start(self, request):
        with self.input_lock:
            cancel = request.get('_cancel_event')
            if isinstance(cancel, threading.Event):
                if cancel in self.pending_starts:
                    self.pending_starts.remove(cancel)
                if cancel.is_set() or self.closing.is_set():
                    self.emit('stopped')
                    return
                if self.session.core:
                    raise ValueError('Сначала отключите текущий профиль.')
                self.stop_requested = cancel
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
        self.restarting = False
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
        for warning in profile_warnings(text):
            self.log(warning, 'warning')
        if self.stop_requested.is_set():
            self.session.stop()
            self.emit('stopped')
            return
        self._analytics('begin', result['capture'], settings['preset'])
        self.log('Ядро запущено; ожидается проверка HTTPS.')
        self._started(result, reconnected=False)
        self._probe(manual=False)


    def _handle_stop(self, request):
        self.restarting = False
        try:
            self.session.stop()
            if not request.get('keep_protection'):
                self.session.protection.release(self.session.broker)
        finally:
            self.healthy = False
            if not self.session.core:
                self._analytics('finish', self._session_totals())
                self.last_profile = None
                self.active_profile_id = None
                self.emit('stopped')
        self.log('Соединение закрыто.' + (' Защита удерживает блокировку до явного отключения.' if self.session.protection.active else ' Собственные сетевые изменения восстановлены.'))


    def _handle_capture_conflict(self, request):
        if request.get('generation') != self.session.generation:
            return
        self.stop_requested.set()
        self.restarting = False
        try:
            self._command({'action': 'stop'})
        finally:
            self.log('Изменился системный прокси или запущен другой VPN. Yukiwire отключён; автоматический захват сети остановлен.', 'warning')


    def _handle_core_exited(self, request):
        if request.get('generation') != self.session.generation or self.stop_requested.is_set():
            return
        core = self.session.core
        if not core or core.process.poll() is None:
            return
        self.stop_requested.set()
        self.emit('core_exited', code=core.process.returncode, diagnostics=core.diagnostics())
        self._command({'action': 'stop', 'keep_protection': True})


    def _handle_probe(self, request):
        self._probe(manual=True)


    def _handle_refresh_environment(self, request):
        self._refresh_environment(manual=True)


    def _handle_get_analytics(self, request):
        self._analytics('overview')


    def _handle_check_updates(self, request):
        self.emit('updates_checking')
        endpoint = self.session.public_endpoints().get('http', {})
        self.emit('updates_checked', **latest_release(endpoint.get('port')))


    def _handle_get_state(self, request):
        self.emit('ready', settings=self.settings, settings_pending=self._settings_pending(),
                  **self.profiles.public(), environment=self._refresh_environment(publish=False),
                  rules=RuleSets().metadata(), warning=None, profile_latencies=self.profile_latencies,
                  profiles_checking=self.profile_check_busy, subscription_busy=self.subscription_busy)
        self._analytics('overview')
        core = self.session.core
        if core and core.process.poll() is None:
            # Publish only public metadata; a temporary config never crosses back to the renderer.
            transient = None
            if not self.active_profile_id:
                raw = self.last_profile or ''
                transient = {'name': 'Временный профиль', 'protocol': 'JSON Xray' if raw.lstrip().startswith('{') else raw.split('://')[0]}
            self.emit('started', pid=core.process.pid, capture=self.session.settings['capture'],
                      reconnected=True, transient=transient, active_settings=self.session.settings,
                      settings_pending=self._settings_pending(), endpoints=self.session.public_endpoints(), ports=list(self.session.listener_ports))
            if self.healthy and self.last_probe_result and self.last_probe_generation == self.session.generation:
                self.emit('probe_result', **self.last_probe_result)
            if self.site_results and self.site_results['generation'] == self.session.generation:
                self.emit('sites_result', results=self.site_results['results'], exit=self.site_results['exit'])
        for entry in self.history:
            self.emit('activity', **entry)


    def _handle_open_browser(self, request):
        if not self.session.core or self.session.core.process.poll() is not None:
            raise ValueError('Сначала подключите профиль Yukiwire.')
        # Browser launch remains a normal-user host responsibility.
        endpoints = self.session.public_endpoints()
        self.emit('browser_requested', proxy_port=endpoints.get('http', {}).get('port', 0))


    def _handle_check_sites(self, request):
        if not self.session.core:
            raise ValueError('Сначала подключитесь.')
        if not self.sites_lock.acquire(blocking=False):
            return
        generation = self.session.generation
        capture = self.session.settings['capture']
        endpoints = dict(self.session.endpoints)
        self.emit('sites_checking')
        def check():
            try:
                report = check_connection(capture=capture, endpoints=endpoints)
                results = report['results']
                with self.state_lock:
                    if generation == self.session.generation and not self.stop_requested.is_set():
                        self.site_results = {'time': int(time.time()), 'generation': generation, **report}
                        self._analytics('update', country=report.get('exit', {}).get('profile', {}).get('country'))
                        self.emit('sites_result', **report)
                        for result in results:
                            self.log(result['target'] + ': ' + result['message'], 'info' if result['accessible'] else 'warning')
            finally:
                self.sites_lock.release()
        threading.Thread(target=check, daemon=True).start()


    def _handle_restart(self, request):
        if request.get('generation') != self.session.generation:
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
                    self._started(result, reconnected=True)
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


    def _handle_save_profile(self, request):
        text = request.get('profile', '')
        name, config = build_config(text)
        validate_config(config)
        for warning in profile_warnings(text):
            self.log(warning, 'warning')
        identity = self.profiles.save(text, request.get('name') or name, 'JSON Xray' if text.lstrip().startswith('{') else config['outbounds'][0]['protocol'], request.get('profile_id'))
        self.emit('profiles', **self.profiles.public())
        self.emit('saved', profile_id=identity)
        self.log('Профиль сохранён с защитой Windows DPAPI.')

    def _handle_update_subscription(self, request):
        if self.subscription_busy:
            raise ValueError('Подписка уже обновляется.')
        identity = request.get('subscription_id')
        previous = self.profiles.subscription(identity) if identity else {}
        url = previous.get('url') if identity else request.get('url', '')
        name = previous.get('name') if identity else request.get('name', '')
        subscriptions.validate_url(url)
        proxy_port = self.session.public_endpoints().get('http', {}).get('port') if self.session.core else None
        self.subscription_busy = True
        self.emit('subscription_updating')
        def update():
            try:
                entries = subscriptions.profiles(subscriptions.download(url, proxy_port), validate_config)
                with self.state_lock:
                    if self.closing.is_set():
                        return
                    self.profiles.update_subscription(url, name, entries, identity)
                    self.emit('profiles', **self.profiles.public())
                    self.emit('subscription_updated', count=len(entries))
            except Exception:
                with self.state_lock:
                    if not self.closing.is_set():
                        self.emit('error', operation='update_subscription', message='Подписка не обновлена. Проверьте HTTPS-ссылку, доступность и совместимость профилей. Прежние данные сохранены.')
            finally:
                with self.state_lock:
                    self.subscription_busy = False
        threading.Thread(target=update, daemon=True).start()

    def _handle_remove_subscription(self, request):
        if self.subscription_busy:
            raise ValueError('Дождитесь завершения обновления подписки.')
        self.profiles.remove_subscription(request.get('subscription_id'))
        self.emit('profiles', **self.profiles.public())
        self.emit('subscription_removed')

    def _handle_check_profiles(self, request):
        if self.session.protection.active:
            raise ValueError('Отключите защищённое подключение перед сравнением профилей: его фильтр не пропускает отдельные проверочные ядра напрямую.')
        if self.profile_check_busy:
            raise ValueError('Проверка профилей уже выполняется.')
        identifiers = request.get('profile_ids', [])
        if not isinstance(identifiers, list) or not 1 <= len(identifiers) <= 20 or not all(isinstance(value, str) for value in identifiers):
            raise ValueError('За один раз можно проверить от 1 до 20 профилей.')
        entries = [self.profiles.get(identity) for identity in dict.fromkeys(identifiers)]
        self.profile_check_busy = True
        self.emit('profiles_checking')
        def check():
            try:
                for entry in entries:
                    if self.closing.is_set():
                        break
                    temporary = Session()
                    result = {'profile_id': entry['id'], 'elapsed_ms': None}
                    try:
                        temporary.start(entry['text'], dict(DEFAULTS, capture='local', preset='all', auto_reconnect=False), self.closing)
                        result['elapsed_ms'] = temporary.probe()['elapsed_ms']
                    except Exception:
                        pass  # Never export raw connection errors or profile addresses.
                    finally:
                        try:
                            temporary.stop()
                        except Exception:
                            # Do not start another probe while its predecessor may still run.
                            with self.state_lock:
                                if not self.closing.is_set():
                                    self.emit('error', operation='check_profiles', message='Не удалось подтвердить остановку проверочного ядра. Проверка профилей прервана.')
                            return
                    with self.state_lock:
                        if not self.closing.is_set():
                            self.profile_latencies[entry['id']] = result
                            self.emit('profile_latency', **result)
            finally:
                with self.state_lock:
                    self.profile_check_busy = False
                    if not self.closing.is_set():
                        self.emit('profiles_checked')
        threading.Thread(target=check, daemon=True).start()


    def _handle_delete_profile(self, request):
        if self.session.core:
            raise ValueError('Сначала отключитесь перед удалением профиля.')
        self.profiles.remove(request.get('profile_id'))
        self.emit('profiles', **self.profiles.public())


    def _handle_export_profiles(self, request):
        self.emit('profile_export_payload', backup=self.profiles.export_profiles())


    def _handle_import_profiles(self, request):
        def validate_profile(text):
            _, candidate = build_config(text)
            validate_config(candidate)
            return 'JSON Xray' if text.lstrip().startswith('{') else candidate['outbounds'][0]['protocol']
        count = self.profiles.import_profiles(request.get('backup'), validate_profile)
        self.emit('profiles', **self.profiles.public())
        self.emit('profiles_imported', count=count)


    def _handle_get_profile(self, request):
        if self.session.core:
            raise ValueError('Отключитесь перед редактированием профиля.')
        self.emit('profile_detail', **self.profiles.get(request.get('profile_id')))


    def _handle_save_settings(self, request):
        settings = normalize_settings(request.get('settings', {}))
        apply_now = bool(self.session.core and settings['reconnect_on_change'] and
                         connection_settings(settings) != connection_settings(self.session.settings))
        if apply_now:
            # Reject invalid routing before saving or interrupting a working connection.
            _, config = build_config(self.last_profile)
            config = diagnostic_config(enable_metrics(apply_routing(config, settings, RuleSets().tags())))
            if settings['capture'] == 'tun':
                if settings['preset'] == 'original':
                    raise ValueError('Для TUN выберите маршрут Yukiwire, а не правила из JSON.')
                config = add_tun(config, new_tun(), settings)
            config = killswitch.configure(config, settings)
            validate_config(config)
        self.settings_file.write(settings)
        self.settings = settings
        self.trace.enabled = settings['debug_logging']
        # Recovery preferences do not require a new core, even with auto-apply disabled.
        for key in ('auto_reconnect', 'reconnect_on_change'):
            self.session.settings[key] = settings[key]
        self.emit('settings', settings=settings, settings_pending=self._settings_pending(), applying=apply_now)
        if apply_now:
            self._apply_settings()
        else:
            self.log('Настройки сохранены.' + (' Применятся при следующем подключении.' if self._settings_pending() else ''))


    def _handle_explain(self, request):
        self.emit('route_explanation', **explain(request.get('target', ''), request.get('settings', self.settings),
                                               RuleSets().membership, request.get('process', '')))


    def _handle_update_rules(self, request):
        action = request.get('action')
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
        if self.session.core:
            download_proxy = self.session.public_endpoints().get('http', {}).get('port')
        metadata = manager.update(validate, download_proxy) if action == 'update_rules' else manager.rollback(validate)
        self.pending_rules = bool(self.session.core)
        self.emit('rules_updated', rules=metadata, settings_pending=self._settings_pending())
        self.log('Версия списков проверена.' + (' Применится при следующем подключении.' if self.pending_rules else ' Новые списки активированы.'))


    def _handle_recover_network(self, request):
        if self.session.core:
            raise ValueError('Сначала отключитесь.')
        result = self.session.guard.recover() if self.session.guard.kind else recover_stale()
        if result.get('requires_elevation'):
            record = self.session.guard.journal.read()
            if not record or not record.get('protected_helper') or not record.get('helper_id'):
                raise ValueError('Остался TUN прежней версии. Завершите его восстановление в прежней версии Yukiwire; журнал сохранён.')
            # A previous package may own the durable lease. Recover with exactly
            # its protected helper, not with the latest version's empty ledger.
            recovery_broker = Broker(component_identity=record['helper_id'])
            try:
                recovery_broker.request('recover')
            finally:
                recovery_broker.close()
            result = self.session.guard.recover() if self.session.guard.kind else recover_stale()
            if result.get('requires_elevation'):
                raise ValueError('Остался TUN прежней версии. Завершите его восстановление в прежней версии Yukiwire; журнал сохранён.')
        if result.get('restored'):
            self.session.guard.kind = None
        self.session.protection.release(self.session.broker)
        self.emit('recovered', **result)


    def _handle_export_diagnostics(self, request):
        report = {'version': VERSION, 'active': bool(self.session.core), 'capture': self.session.settings['capture'],
                  'preset': self.session.settings['preset'], 'https_verified': self.healthy,
                  'failed_checks': self.session.failure_count, 'reconnects': self.session.reconnect_count,
                  'network_journal_present': self.session.guard.journal.path.exists(),
                  'last_site_check': self.site_results,
                  'technical_events': self.trace.export(),
                  'core_diagnostics': self.session.core.diagnostics() if self.session.core else []}
        target = RUNTIME / 'diagnostics.json'
        atomic_write(target, json.dumps(report, ensure_ascii=False, indent=2).encode())
        self.emit('diagnostics_exported', path=str(target))

    def _handle_clear_diagnostics(self, request):
        self.trace.clear()
        (RUNTIME / 'diagnostics.json').unlink(missing_ok=True)
        self.emit('diagnostics_cleared')


    @serialized
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
            except Exception as exc:
                self._complete_probe(generation, error=exc)
            else:
                self._complete_probe(generation, result=result)
            finally:
                with self.state_lock:
                    self.probing = False
                    self.probe_lock.release()
                    if self.session.generation != generation and self.session.core and not self.stop_requested.is_set() and not self.closing.is_set():
                        self._probe(manual=False)
        threading.Thread(target=check, daemon=True).start()

    @serialized
    def _complete_probe(self, generation, result=None, error=None):
        if self.session.generation != generation or self.stop_requested.is_set() or self.closing.is_set():
            return
        if error is None:
            self.healthy = True  # HTTP denial still proves verified TLS transport.
            self.failed_checks = 0
            self.last_probe_result = result
            self.last_probe_generation = generation
            self.emit('probe_result', **result)
            self._analytics('update', latency=result['elapsed_ms'])
            self.log('HTTPS-соединение проверено; сертификат действителен.')
        else:
            self.healthy = False
            self.failed_checks += 1
            self.session.failure_count += 1
            message = 'HTTPS не прошёл (%s).' % type(error).__name__
            diagnostics = self.session.core.diagnostics() if self.session.core else []
            self.emit('error', message=message, operation='probe', diagnostics=diagnostics)
            self.log(message, 'warning')

    def _settings_pending(self):
        return bool(self.session.core and (self.pending_rules or connection_settings(self.settings) != connection_settings(self.session.settings)))

    def _started(self, result, reconnected):
        self.pending_rules = False
        self.emit('started', pid=result['pid'], capture=result['capture'], reconnected=reconnected,
                  active_settings=self.session.settings, settings_pending=self._settings_pending(),
                  endpoints=self.session.public_endpoints(), ports=list(self.session.listener_ports))

    def _apply_settings(self):
        """One controlled restart; retain the saved draft and restore the old session on failure."""
        if self.stop_requested.is_set() or self.closing.is_set():
            return
        previous = dict(self.session.settings)
        self.restarting = True
        self.healthy = False
        self.site_results = self.last_probe_result = self.last_probe_generation = None
        self.failed_checks = 0
        self.emit('reconnecting', reason='settings')
        try:
            # Never launch another core unless ownership and network cleanup succeeded.
            self.session.stop()
            if not killswitch.enabled(self.settings):
                self.session.protection.release(self.session.broker)
            if self.stop_requested.is_set() or self.closing.is_set():
                return
            try:
                result = self.session.start(self.last_profile, self.settings, self.stop_requested)
            except NetworkConflict:
                raise  # A foreign VPN is not permission to retake the network.
            except Exception as exc:
                if self.stop_requested.is_set() or self.closing.is_set():
                    return
                if self.session.core or self.session.guard.kind:
                    raise  # Failed cleanup: retain recovery ownership, do not start again.
                try:
                    result = self.session.start(self.last_profile, previous, self.stop_requested)
                except Exception:
                    raise ValueError('Настройки сохранены, но переподключение не удалось. Подключитесь повторно.') from None
                if not self.stop_requested.is_set():
                    self._started(result, reconnected=True)
                    self._probe(manual=False)
                    raise ValueError('Настройки сохранены, но не применены. Восстановлено предыдущее подключение.') from exc
                return
            if self.stop_requested.is_set() or self.closing.is_set():
                return
            self.session.reconnect_count += 1
            self._started(result, reconnected=True)
            self.log('Изменения применены. VPN переподключён.')
            self._probe(manual=False)
        finally:
            self.restarting = False
            if self.stop_requested.is_set() or self.closing.is_set():
                self.session.stop()
            if not self.session.core:
                self.healthy = False
                self.emit('stopped')
                self._analytics('finish', self._session_totals())

    def _monitor(self):
        while not self.closing.wait(2):
            self._monitor_step()

    @serialized
    def _monitor_step(self):
        core = self.session.core
        generation = self.session.generation
        if not core or self.restarting:
            return
        if core.process.poll() is not None:
            self.healthy = False
            if self.session.settings['auto_reconnect'] and not self.stop_requested.is_set():
                if not self.restarting:
                    self.restarting = True
                    self.commands.put({'action': '_restart', 'generation': generation})
            else:
                self.commands.put({'action': '_core_exited', 'generation': generation})
            return
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

    @serialized
    def _check_capture(self, generation, environment=None):
        mode = self.session.settings['capture']
        if generation != self.session.generation or mode == 'local' or self.stop_requested.is_set() or self.restarting:
            return
        collision = dict(environment) if environment is not None else conflicts(own_proxy=self.session.own_proxy())
        if collision.get('check_failed'):
            collision['other_vpn'] = True
        if mode == 'system' or (mode == 'tun' and self.session.settings['tun_system_proxy']):
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
        with self.input_lock:
            self.stop_requested.set()
            self.closing.set()
            for cancel in self.pending_starts:
                cancel.set()
        core = self.session.core
        if core and core.process.poll() is None:
            try:
                core.process.terminate()
            except OSError:
                pass
        with self.state_lock:
            try:
                self.session.stop()
                self.session.protection.release(self.session.broker)
            finally:
                if self.session.broker:
                    self.session.broker.close()
                self.healthy = False
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
