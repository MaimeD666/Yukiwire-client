# Обзор Yukiwire

Актуализировано: 2026-10-16 по локальным исходникам. Начинай с этого файла и [state.md](state.md). Правила обновления — в [AGENTS.md](../../AGENTS.md).

## Продукт и платформа

Yukiwire 0.5 — клиент Xray для Windows 10/11 x64. Репозиторий: `MaimeD666/Yukiwire-client`. Импорт VLESS, VMess, Trojan, Shadowsocks, Hysteria2 и JSON Xray, включая userspace WireGuard; библиотека/HTTPS-подписки/QR, маршрутизация, игровые исключения, диагностика и статистика. Версия и результаты публикации фиксируются в state.md.

Режимы захвата: локальный прокси (`local`), системный прокси (`system`), TUN (`tun`). В TUN отдельно включается системный прокси (`tun_system_proxy`) для приложений, учитывающих настройки Windows. Чистый TUN и TUN с прокси — самостоятельные сценарии проверок.

UI написан на HTML/CSS/JavaScript без npm-сборки. Windows-хост — C# WPF и WebView2, требуется .NET Framework 4.8. Python-бэкенд использует стандартную библиотеку и Windows API через ctypes. `requirements-build.txt` не устанавливает Python-пакеты; `requirements-dev.txt` закрепляет Playwright для проверок UI.

## Карта кода

Все пути в таблице относительно корня репозитория.

| Область | Файлы и точки входа | Ответственность |
| --- | --- | --- |
| Запуск из исходников | `run.cmd`, `yukiwire/__main__.py`, `scripts/build_native.py` | Собрать/найти нативный хост и запустить его с путями проекта и Python |
| Windows-хост | `native/WebShell.cs`, `native/Launcher.cs`, `native/app.manifest` | Окно, WebView2, трей, мост команд, жизненный цикл, передача работы сетевому помощнику |
| Помощник TUN | `native/NetworkBroker.cs`, `native/NetworkPolicy.cs`, `native/NetworkCleanup.cs`, `native/ProtectedStorage.cs`, `native/NetworkInstaller.cs`, `yukiwire/broker.py`, `yukiwire/privilege.py` | Защищённая установка в Program Files; узкий native IPC, проверка конфигурации, Job Object и очистка собственного TUN. Python остаётся обычным процессом |
| Интерфейс | `ui/index.html`, `ui/app.js`, `ui/styles.css` | Формы, черновики, отображение событий сервиса, темы и размеры окна |
| Сессия | `yukiwire/session.py`: `Session`, `validate_config` | Владение ядром/захватом, endpoints, запуск/остановка и восстановление. backend сохраняет импорт-алиас Session |
| Команды | `yukiwire/backend.py`: `ApplicationService` | Сериализованные handlers, настройки, переподключение, фоновые задачи и мониторы |
| Kill switch | `native/NetworkFilter.cs`, `native/NetworkKillSwitch.cs`, `yukiwire/killswitch.py` | Опциональная постоянная WFP-политика и отдельный журнал; живые проверки и оставшаяся матрица — в state.md |
| DNS / профили / журнал | `yukiwire/dns_config.py`, `yukiwire/subscriptions.py`, `yukiwire/diagnostics.py`, `ui/assets/jsQR.js` | Раздельный DNS, подписки, локальный QR, безопасные технические события |
| Профиль → Xray | `yukiwire/config.py`: `build_config`, `other_link` | Парсинг ссылок/JSON, ограничение входной конфигурации, управляемые local inbound |
| Правила | `yukiwire/routing.py`: `DEFAULTS`, `build_rules`, `apply_routing`, `explain` | Настройки, порядок маршрутов, игровые процессы, объяснение выбора маршрута |
| Списки | `yukiwire/geodata.py`: `RuleSets` | Загрузка, проверка, активация, откат и чтение наборов маршрутов |
| Сеть Windows | `yukiwire/network.py`: `ProxyLease`, `NetworkGuard`, `add_tun`, `recover_journal` | Прокси, журнал владения сетью, подготовка и очистка TUN |
| Наблюдение Windows | `yukiwire/windows_snapshot.py` | Процессы, интерфейсы, маршруты и обнаружение чужого захвата |
| Аварийное восстановление | `yukiwire/watchdog.py`, `yukiwire/recovery.py`, `yukiwire/startup.py`, `scripts/*-tun.ps1`, `scripts/startup-recovery.ps1` | Watchdog, восстановление по журналу, задача следующего входа Windows |
| Процесс ядра | `yukiwire/process.py`: `CoreProcess` | Передача конфигурации через stdin, Job Object, контроль завершения Xray |
| Диагностика | `yukiwire/health.py`: `diagnostic_config`, `probe_https`, `check_sites` | Проверка VPN-транспорта, фактического TUN-пути, HTTP-доступности и страны выхода |
| Данные и статистика | `yukiwire/storage.py`, `yukiwire/paths.py`, `yukiwire/analytics.py`, `yukiwire/telemetry.py` | DPAPI, атомарная запись, история сессий и счётчики Xray |
| Браузер | `yukiwire/browser.py`, обработчик в `native/WebShell.cs` | Отдельный профиль браузера, явный локальный прокси, запуск от обычного пользователя |
| Поставка и проверки | `scripts/build_*.py`, `scripts/verify_*.py`, `tests/`, `packaging/windows/Yukiwire.iss`, `.github/workflows/` | Сборка, установщик, автоматические проверки и публикация |

Обычный путь команд: WebView2 → WPF → Python `ApplicationService` → `Session` → Xray. Для TUN обычный Python вызывает установленный `Yukiwire.Network.exe` через проверенный named pipe. Native helper запускает закреплённый Xray; очистка выполняется через IP Helper API и системный netsh; собственные PID/времена запуска/идентичность TUN сохраняет в защищённом журнале. Первичная установка компонента и его запуск требуют UAC; helper живёт до выхода backend и переиспользуется при переподключении. `native/NetworkWorker.cs` со старым Python-worker теперь компилируется только в тестовый host. Production IPC, TUN/system/combined и WFP проходят отдельную сетевую приёмку в CI; точные результаты — в state.md.

## Настройки и сетевые контракты

Источник значений по умолчанию — `routing.DEFAULTS`: `capture='local'`, `preset='ru-direct'`, `dns='system'`, `auto_reconnect=True`, `reconnect_on_change=False`, `tun_system_proxy=False`, `kill_switch=False`, `debug_logging=False`, `ru_ip=False`, `game_mode=False`. Список игр изначально содержит `dota2.exe`.

| Значение `preset` | Интерфейс / поведение |
| --- | --- |
| `ru-direct` | «Все, кроме РФ»; определение по доменам, дополнительно по RU IP |
| `all` | «Все сайты» через VPN с учётом исключений |
| `selected` | «По списку»: выбранные/заблокированные домены через VPN, остальное напрямую |
| `original` | Правила исходного JSON; игровые исключения не применяются, TUN отклоняется |

Пользовательские правила проверяются в порядке: блокировка → игры напрямую → явное VPN → явное direct. Далее идут правила списков, локальной сети и выбранного режима. Точный порядок и поведение без geodata проверять в `build_rules`; не сводить его только к названиям кнопок.

Сессия выделяет случайные loopback-порты (`yukiwire/endpoints.py`). SOCKS, диагностический HTTP и HTTP-метрики используют одноразовые пароли; метрики читаются без subprocess. Диагностический listener допускает только встроенные цели/443. Pure TUN не открывает обычные HTTP/SOCKS. Local/system/combined сохраняют обычный HTTP без auth для WinInet — это известное ограничение доступа со стороны локальных процессов. Фиксированные порты остаются только совместимыми значениями по умолчанию самостоятельных построителей/старых тестов; UI/браузер/lease получают endpoints активной сессии.

`add_tun` задаёт MTU 1500, адреса `172.29.250.1/30` и `fd72:756b:6977::1/126`, DNS `172.29.250.2`, захват IPv4/IPv6 через маршруты `/1`. `dns_config.py` строит раздельный DNS: direct-домены используют физический DNS, снятый до захвата, proxy-домены — настраиваемый DoH через VPN. `dns='doh'` отправляет весь DNS через VPN. Приоритет доменных правил сохраняется; процессы игр не определяются по общему запросу Windows DNS. `autoSystemWfpBlockLeak=['dns','misconfigtun']` не является общим kill switch.

## Данные и сборки

- В исходниках `RUNTIME = ROOT/runtime`, `STATE = runtime/state`, ядро — `runtime/core/xray.exe`. В portable с `portable.json` runtime совпадает с корнем сборки, состояние — `state/`, ядро — `core/xray.exe`.
- Профили/URL подписок и настройки: `profiles.dpapi` / `settings.dpapi`; сетевой журнал: `network-lease.dpapi`, маркер постоянной WFP-защиты: `kill-switch.dpapi`. Реальные значения не нужны для понимания архитектуры.
- Установщик сейчас per-user: `%LOCALAPPDATA%/Programs/Yukiwire`, `PrivilegesRequired=lowest`. Сетевая часть устанавливается отдельно в `%ProgramFiles%/YukiwireNetwork/<hash-helper>`; остальная программа остаётся per-user/portable. Legacy TUN-журнал требует завершения восстановления старой версией, пока новая реализация не может подтвердить безопасную очистку. Защищённая установка проверяется в CI; миграция legacy-сессий требует старого recovery.
- `build_portable.py` собирает явный список публичных файлов и SHA256-манифест. Новая папка контекста автоматически в пакет приложения не включается. Установщик проверяет этот payload, сохраняет приватное состояние и блокирует обслуживание при работающем хосте/незавершённом журнале.
- Версия Xray в загрузчике — `v26.9.30`, SHA256 архива закреплён независимо в исходниках. Embedded Python в `download_python.py` — `3.14.8`; исходники/CI используют минимум/версию 3.11. Эти значения описывают исходники, а не проверенный состав установленного приложения.

## Основные команды

Выполняются из корня репозитория на Windows с Python x64. Загрузчики обращаются к сети; запуск приложения открывает окно.

```powershell
python scripts/download_core.py
python scripts/download_wintun.py
python -m yukiwire
```

Для сборки: `python scripts/build_native.py`, затем `python scripts/build_portable.py` и `python scripts/build_installer.py`. Portable по умолчанию требует Wintun; вспомогательные скрипты загружают WebView2 SDK и embedded Python. Имена актуальных артефактов — `dist/Yukiwire-0.5-win-x64.zip` и `dist/Yukiwire-0.5-win-x64-setup.exe`.

`build_portable` включает неизменённый RU snapshot `88549b306b2b19c6e19ddd09fe9f27f4fb92df10` из `download_rules.py`, с независимыми SHA256 и лицензией; исходные runtime/core geodata при сборке не перезаписываются. Setup включает подписанный полный WebView2 x64 (offline), .NET 4.8 остаётся предварительным требованием. Чистая машина без Runtime ещё не проверена.

Команды тестов и их внешние эффекты описаны в [testing.md](testing.md). Checks выполняет тесты, сборку и проверки UI/пакетов. Network acceptance меняет сеть только на одноразовой Windows VM GitHub. Release запускается по изменению version.py в main или тегу v*, собирает пакет и проверяет его же ZIP с bundled Python в сетевой приёмке. Только затем создаёт тег, проверяет загруженные ZIP/Setup/SHA256SUMS и публикует релиз. Actions закреплены SHA; результаты запусков — в state.md.
