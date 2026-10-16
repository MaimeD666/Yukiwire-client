# Проверки и защита от регрессий

Актуализировано: 2026-10-16 по существующим тестам и CI. Команды ниже — инструкция для будущих изменений; актуальные выполненные проверки записаны в state.md.

## Выбор уровня

Для документации проверять ссылки/пути и согласованность с кодом. Для изменения поведения — сначала подходящие модульные тесты; затем только необходимые интеграции. Успешные mocks не доказывают работу настоящего TUN, UAC или браузерного видео.

Пример набора для изменений сети/настроек, из корня проекта в PowerShell:

```powershell
$yukiwireTestModules = @('test_config', 'test_routing', 'test_network', 'test_service', 'test_settings_apply', 'test_health')
foreach ($yukiwireTestModule in $yukiwireTestModules) {
    python -B -m unittest discover -s tests -p "$yukiwireTestModule.py" -v
    if ($LASTEXITCODE -ne 0) { throw "Failed: $yukiwireTestModule" }
}
```

Эти файлы проверяют основные контракты с подстановками внешних операций; требуется Windows для модулей с Windows API. При изменении самих тестов заново проверить их эффекты.

Полный набор, используемый CI:

```powershell
python -B -m unittest discover -s tests -v
```

Он включает реальные процессы Windows, локальные listeners/Xray, DPAPI и регистрацию тестовой задачи Планировщика. Интеграции Xray выделяют endpoints динамически; они работают с локальными фикстурами и не должны захватывать OS-сеть. Все проверки cleanup отслеживают только фактические порты своего ядра. Пропуск интеграции из-за отсутствующего Xray учитывать как пропуск, а не успех. `test_startup_integration.py` создаёт и удаляет реальную тестовую задачу; `test_watchdog_integration.py` завершает только собственные тестовые процессы и использует файловую имитацию сети.

## Карта регрессий

Пути тестов относительно `tests/`.

| Контракт | Существующие проверки | Что дополнительно подтвердить при изменении |
| --- | --- | --- |
| Импорт и управляемая конфигурация | `test_config.py`, `test_core_integration.py` | Старые ссылки/JSON, обязательные поля, запрет чужих inbound/API/log; кандидат принимается закреплённым Xray |
| Порядок маршрутов и игры | `test_routing.py`, `test_game_integration.py`, `test_core_integration.py` | Конфликтующие block/game/proxy/direct, TCP и UDP, RU IP/домены, отсутствие списков, original JSON |
| TUN + системный прокси | `test_service.py`, `test_network.py`, `test_routing.py` | Готовность TUN и VPN до proxy apply, ошибка/отмена запуска, общий recovery, чистый TUN без proxy apply |
| Владение сетью | `test_network.py`, `test_windows_snapshot.py`, `test_watchdog_integration.py`, `test_startup.py`, `test_startup_integration.py` | Чужой прокси/PAC сохраняется; собственный TUN очищается; PID reuse, старый lease, неполная очистка и недостаточные права |
| Сохранение/применение настроек | `test_settings_apply.py`, `test_service.py` | Отложенное применение, включение автоприменения, ошибка сохранения/валидации, rollback, stop, устаревшие события, UAC handoff |
| Достоверная диагностика | `test_health.py`, `test_service.py`, `test_core_integration.py` | Не маскировать TUN-сбой успехом proxy; различать TLS, HTTP 403 и доступность; диагностический outbound не становится direct |
| Приватные данные и статистика | `test_storage.py`, `test_analytics.py`, `test_browser.py` | DPAPI, атомарность записи, сохранение профилей/истории, браузер без повышения прав; отчёты без секретов |
| Списки маршрутов | `test_geodata.py`, `test_routing.py` | Повреждение загрузки, проверка blob, переключение/откат и совместимость с текущим ядром |
| Процессы и закрытие | `test_process.py`, `test_service.py`, `test_watchdog_integration.py` | Завершение своего ядра, смерть владельца, renderer recovery без перезапуска сессии, сохранение recovery при ошибке |
| Поставка | `test_packaging.py`, `test_installer.py` | Точный manifest, непубличные файлы исключены, обновление/удаление сохраняют state, активный host/lease блокирует обслуживание |

Для совместного режима уже существуют точечные тесты:

- `test_service.py`: `test_combined_capture_detects_disabled_proxy_without_reapplying_it`.
- `test_network.py`: `test_combined_capture_keeps_foreign_proxy_but_removes_own_tun`, `test_combined_capture_restores_proxy_even_when_tun_cleanup_needs_retry`, `test_plain_tun_does_not_apply_a_system_proxy`.
- `test_health.py`: `test_tun_probe_uses_os_route_without_an_explicit_proxy`, `test_tun_failure_is_not_hidden_by_working_vpn_proxy`.

## UI, нативный хост и поставка

`python -m pip install -r requirements-dev.txt`, затем `python scripts/verify_ui.py`: Playwright с Edge, интерфейс с изолированным backend, без реальных профилей и захвата сети. Скрипт сохраняет отчёт/скриншоты в `runtime/ui-checks`. Проверять узкое окно 500×740, большие окна, масштабирование, обе темы, черновики, отложенное применение и отмену.

`python scripts/build_native.py` проверяет компиляцию C#-хоста и может загрузить WebView2 SDK. Для затронутых сценариев существуют `verify_native.py`, `verify_window_bounds.py`, `verify_host_lifecycle.py`, `verify_helper_crash.py`, `verify_browser_proxy.py`. Перед запуском смотреть входные параметры и предусловия конкретного скрипта: это реальные процессы/окна, часть сценариев использует Xray и локальные порты.

После изменений упаковки использовать актуальный путь без устаревшего суффикса `preview`:

```powershell
python scripts/build_portable.py
python scripts/verify_portable.py dist/Yukiwire-0.5-win-x64.zip --native
python scripts/build_installer.py
python scripts/verify_installer.py
```

Потребуются загруженные ядро/Wintun и инструменты установщика (`scripts/download_installer_tools.py`). Проверка установщика действительно устанавливает/обновляет/удаляет тестовую копию с отдельной регистрацией; это не только анализ архива. Полный порядок CI — в [.github/workflows/check.yml](../../.github/workflows/check.yml).

## Реальная сеть: отдельная приёмка

Проводить в согласованном рабочем окне или изолированной Windows-среде. Учитывать уже данное разрешение пользователя и активное подключение. Пользователь разрешил испытания, но активное подключение и zapret нельзя останавливать вне предусмотренного сценария.

`scripts/acceptance.py` без `--exercise` выполняет предварительный этап; `--exercise` запускает жизненный цикл подключения/сбоев. Для `system`/`tun` нужен явный `--allow-network-changes`; TUN-сценарий скрипта требует повышенных прав. `technical-test.cmd` без аргументов уже включает `--exercise --capture local` и может использовать сохранённый профиль: не считать его безвредной проверкой синтаксиса.

Минимальная матрица для изменений помощника, портов, маршрутов или восстановления:

1. `local`, `system`, чистый `tun`, `tun` + `tun_system_proxy`: запуск, ручная остановка, ошибки старта и смена режима.
2. Падение Xray/помощника/хоста, отмена UAC/подключения, восстановление после незавершённой очистки. Проверить отсутствие повторного захвата после команды stop и сохранение чужого прокси.
3. Сохранение активных настроек с выключенным и включённым `reconnect_on_change`, невалидный кандидат и возврат прежней сессии. Проверить UAC при переходе в TUN.
4. В совместном режиме: браузер, использующий настройки Windows без явного `--proxy-server`, и отдельный TCP/UDP-трафик через TUN. Проверить оба пути до и после переподключения.
5. YouTube: обычная страница, связанные домены и реальное продолжительное воспроизведение. Записать режим, релевантные правила, наличие сетевого фильтра, длительность и результат без профиля сервера/cookies. Не выдавать HTTP 200 страницы за проверенное видео.
6. Диагностика чистого TUN должна по-прежнему обнаруживать его сбой, даже если браузер через системный прокси работает. Отдельно проверить игровой direct и block, DNS и IPv4/IPv6.
7. При изменении восстановления — сон/пробуждение, выход/вход Windows и перезагрузка; при изменении поставки — чистая машина и отсутствие WebView2/интернета. Такие проверки не заменяются mocks.

Исторический TESTING.md сообщал об ограничениях живых проверок совместного режима, нового UAC-перехода и длительного видео. До новых испытаний эти границы остаются открытыми.

## Запись результата

В [state.md](state.md) и карточке аудита фиксировать дату, ревизию при наличии, точную команду/сценарий, окружение, результат, пропуски и оставшуюся неопределённость. Большие отчёты хранить в исключённых `runtime/`/`build/`; сюда переносить короткий обезличенный вывод. Отсутствующий локальный отчёт не считать доказательством, доступным следующему агенту.

## Новая граница прав (аудит 1/7)

`test_network_policy.py` компилирует точную native policy в обычный harness без UAC и проверяет отказ привилегированных файловых/сетевых параметров; `test_broker.py` проверяет порядок journal-before-start, serial и обрыв связи, `test_privilege.py` — ACL/пути. Это не доказательство живого TUN.

`python scripts/verify_network_component.py --install` действительно запрашивает UAC и устанавливает versioned helper в Program Files. Он проверяет production IPC и prepare/stop/EOF, **никогда не отправляет start**, не создаёт адаптер и не меняет системный proxy. После него остаётся защищённая версия компонента. Не запускать неявно как unit test. Живая матрица выше обязательна отдельно.

`verify_production.py` должен подтвердить отказ `--network-worker` и отсутствие legacy Python worker. Тестовые `verify_native`/`verify_helper_crash` используют отдельные mutex/cache/state и не читают реальные source-настройки при public fixture. Не путать эти проверки старого тестового transport worker с новой production TUN-границей.


## Новые обязательные сценарии

- `test_broker_pipe.py`: настоящий named pipe без UAC, одновременное ожидание чтения/запись большого кадра, отмена ожидания клиента/чтения, ограничение кадра и проверка PID. Это обязательная регрессия блокировки синхронного duplex. `network-acceptance.yml` запускает production helper и `verify_network_live.py` на одноразовой Windows VM; последний скрипт явно отказывается работать вне elevated GitHub-hosted runner.

- `test_dns.py`: настоящий Xray и два локальных UDP DNS-сервера; direct/proxy/block/пересечения/fallback. Живые DNS IPv6/TUN проверять отдельно.
- `test_subscriptions.py`, `test_profile_tasks.py`, `test_storage.py`: HTTPS/размер/атомарность/dedup, stop во время фоновой загрузки, запрет поздней записи после close, отдельное ядро замера и отказ при ошибке cleanup.
- `test_config.py`, `test_core_integration.py`, `test_network_policy.py`: Hysteria2/Salamander, KCP без неработающего seed, userspace WG, запрет masquerade-файлов/kernel WG. Приём конфигурации ядром не подтверждает подключение к каждому реальному серверу.
- `test_diagnostics.py`, `test_process.py`: default-off, allowlist/rotation/export/clear, отсутствие raw секретов, отказ диагностического sink не прерывает чтение процесса/IPC.
- `test_killswitch.py`, `test_network_filter.py`: journal-before-arm/start, crash/reconnect удерживают, manual stop снимает, ABI structs. Эти проверки **не меняют WFP**. Живая проверка требует отдельной Windows-среды и административного доступа для снятия фильтров: TCP/UDP, IPv4/IPv6/DNS, уже открытые соединения, смерть ядра/helper/host, BFE/reboot, отмена UAC и явное восстановление. Проверять system и TUN, недоступный/старый helper и сохранение маркеров при ошибке.
- UI должен показывать «Снять блокировку» без активного ядра, не считать отсутствие сессии отсутствием постоянных фильтров. Local сохраняет настройку kill switch, но не включает её.
- Пакет: bundled RU manifest/хэши/rollback, оба network payload, production без test worker. `verify_installer.py` использует отдельный mutex и регистрацию; проверяет блокировку update/uninstall обоими журналами. Требует существующий WebView2, не доказывает offline-установку prerequisite.

Для `verify_release.py` использовать отдельную папку ровно с финальными ZIP, Setup и SHA256SUMS.txt. В dist могут оставаться тестовые/промежуточные файлы; не выдавать всю dist за набор релиза. После реальной публикации релиза отдельно проверяются загруженные размеры/digests; создание ветки/PR такой проверкой не является.

## Сетевая приёмка версии 0.5 в CI

`network-acceptance.yml` использует только elevated GitHub-hosted Windows runner и публичный синтетический VLESS peer; сохранённые профили не читаются. `verify_network_live.py` вне этой среды отказывается работать. Проверяются system/pure TUN/combined, реальные HTTPS и счётчики каждого inbound, proxy/foreign snapshots, остановка/EOF, WFP после аварии ядра/помощника и явное восстановление. DNS сравнивает ответы одного UDP-резолвера до/во время/после защиты, включая ранее открытый UDP socket. Отсутствие рабочей IPv6-связности отмечается как SKIP, а не успех. VM имеет отключённый UAC: это не тест диалога согласия на рабочем ПК.

`test_network_cleanup.py` проверяет точные x64 IP Helper layouts и отказ чужого адаптера без изменений сети. Реальная очистка проверяется только в сетевой приёмке. Для IPC дополнительно обязателен test_broker_pipe с настоящим Windows pipe.

В Release после Checks выполняется `verify_network_package.py <ZIP>`: проверка манифеста, извлечение в отдельную папку и production helper/live-сценарии именно с bundled Python и компонентом из публикуемого ZIP. Test-only аварийный процесс снимает только WFP-ключи данного компонента/учётной записи; он не входит в пакет. Публикация зависит от успеха этой проверки, затем проверяются размеры/digests всех загруженных assets.
