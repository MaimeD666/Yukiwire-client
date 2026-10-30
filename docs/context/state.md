# Текущее состояние

Обновлено: 2026-10-30. Основание: текущее дерево и выполненные проверки; версия исходников 0.6. Опубликован v0.6, ревизия 8cc1f015abe11134c47092dbcafbae47c7feee42; публичный latest и тег проверены.

## Выпуск Hysteria 2, 30 октября

- Расширен существующий импорт Hysteria2: списки/диапазоны портов через штатный UDPHop (30 секунд), безопасное сочетание insecure=1 + pinSHA256, проверка ошибочных/неоднозначных адресов без вывода секретов. Подписки принимают HY2 без учёта регистра. D-012 описывает контракт и источники.
- Native policy пропускает ограниченный клиентский UDPHop без remoteIPs, сохраняя pure TUN/combined. AmneziaWG/vpn:// требуют отдельного движка и явно не поддерживаются; VLESS из Amnezia уже совместим.
- В пакет включён существующий hotfix probe_transport от 27 октября. Активное подключение пользователя и zapret не останавливались, установленный клиент в этой задаче не менялся.
- Локально: test_config 20, test_subscriptions 6, test_network_policy 5, test_core_integration 7, test_routing 18, test_game_integration 2, test_network 24, test_health 16, test_service 30, test_settings_apply 15, test_killswitch 6, test_release 3, test_packaging 3 — 155 OK. test_hysteria_integration — 3 OK: реальные TCP/UDP, Salamander, UDPHop wrapper, неверные pin/auth. После финального ограничения диапазонов config/policy и Hysteria-интеграция повторены успешно. Полный discover локально не запускался.
- Переключение между разными удалёнными портами после 30 секунд и внешний Hysteria-сервер не проверены. Gecko/Realms и AWG не реализованы. Первый CI 088c0f2 прошёл полный unittest и VLESS-матрицу; Hysteria system прошёл, TUN упал из-за loopback-сервера стенда: Windows отвергает UDP к 127.0.0.1 при привязке сокета к физическому NIC (локально воспроизведён WSAEADDRNOTAVAIL с sockopt.interface без изменения сети). Стенд перенесён на собственный IPv4 физического NIC одноразовой VM, auth/obfs случайные в памяти. Производственная конфигурация не ослаблялась. Повторная [Network acceptance](https://github.com/MaimeD666/Yukiwire-client/actions/runs/41065612361) на 8cc1f01 прошла: VLESS и Hysteria2+Salamander+pin+UDPHop в system/pure TUN/combined, WFP, TCP/UDP DNS, аварии и восстановление. IPv6 DNS — SKIP из-за отсутствия рабочей IPv6-базы VM.
- Локальная сборка 0.6 повторена после финальных изменений. verify_portable подтвердил allowlist/SHA256, изоляцию bundled Python, реальные трафик/метрики и start/stop без захвата сети; установщик собран. Hysteria-интеграция также прошла с bundled Python 3.14.8. [Checks](https://github.com/MaimeD666/Yukiwire-client/actions/runs/41065612151) и [Release](https://github.com/MaimeD666/Yukiwire-client/actions/runs/41065612108) прошли: 234 теста после загрузки ядра (до загрузки 15 явных SKIP), UI в 8 размерах/DPI, browser/helper crash, portable/native, установка/обновление/удаление тестовой копии с сохранением private sentinel. Финальный ZIP с bundled Python отдельно прошёл ту же сетевую приёмку. Состав, размеры и digests загруженных assets проверены перед публикацией. Для установки: отключить Yukiwire, завершить восстановление и выйти через трей; запустить dist/Yukiwire-0.6-win-x64-setup.exe в прежнюю папку, сохранив профили/настройки. Первый TUN запросит UAC для обновлённого компонента.



## Публикация 0.6

[GitHub Release v0.6](https://github.com/MaimeD666/Yukiwire-client/releases/tag/v0.6) опубликован из `8cc1f015abe11134c47092dbcafbae47c7feee42`. Тег commit-типа, latest=v0.6, draft=false, prerelease=false. Ровно три asset:

| Файл | Размер | SHA256 |
| --- | ---: | --- |
| Yukiwire-0.6-win-x64.zip | 63 947 849 | b45e822084b8c00853791eb1accea2dcedf6d54c184d06cab09bfafb454300eb |
| Yukiwire-0.6-win-x64-setup.exe | 262 484 155 | e936a6f51fc9788c52620ee1ce9197ad36f0d9ab7543328dc56f088d03dbcbb1 |
| SHA256SUMS.txt | 190 | 503145b03c00a69ad3e4a758209cde7aebcdcb830fdfc8dcce998e27871d3425 |

Публичные ZIP/Setup/SHA256SUMS скачаны в `dist/release-v0.6/`, локально сверены размеры/SHA256 и выполнен verify_release. Установщик для пользователя: `dist/release-v0.6/Yukiwire-0.6-win-x64-setup.exe`.

Изменения опубликованы через GitHub connector; локальные unborn HEAD и исходный индекс сохранены. Локальный refs/remotes/origin/main ещё указывает на c93004d и не отражает текущую main. Последующая правка контекста фиксирует выпуск, не меняет его тег или пакеты.

## Исправление проверки готовности (27 октября)

Готовность VPN ранее зависела от единственной HTTPS-цели. Отказ TLS на ней отвергал соединение, даже когда другие цели были доступны через тот же VPN. `health.probe_transport` теперь последовательно проверяет до трёх встроенных HTTPS-целей с проверкой сертификата и отменой. `Session.start/probe` используют его; диагностика настоящего TUN остаётся отдельной. Контракт — D-002. Исправление включено в проверенный пакет 0.6.

## Предыдущая публикация 0.5

Исправления объединены в исходную `main`: [PR #1](https://github.com/MaimeD666/Yukiwire-client/pull/1), ревизия `81510fd6f14e5d0593f9d58595bc0e2c6b05f826`. Опубликован [v0.5](https://github.com/MaimeD666/Yukiwire-client/releases/tag/v0.5), тег указывает на эту ревизию; публичный latest проверен. В релизе ровно ZIP, Setup и SHA256SUMS.txt. Последующая правка этих документов фиксирует результат выпуска и не меняет код/пакеты. Точный реестр — [audit.md](audit.md).

Исходная main — `5fea661b26b5837d14f55ff29302b1a66ae20200`. Локальный HEAD исходно unborn main; прежний индекс содержит staged-дерево и сохранён. Для публикации использован отдельный `runtime/audit-compare.index` и Git `runtime/dev-tools/mingit/cmd/git.exe`; refs/remotes/origin/main синхронизирован, исходный индекс/HEAD сохранены. Эти документы описывают исходники, а не установленную пользовательскую программу.

Собственная подпись явно не требуется пользователю: аудит 4 — принятое ограничение. Активный VPN и zapret на его ПК в этом продолжении не отключались; живые изменения сети перенесены на одноразовую Windows VM GitHub.

## Реализованный объём

- Повышенный Python исключён из production. UI/Python остаются обычными, native helper/Xray/Wintun устанавливаются отдельно в защищённый Program Files. Ограниченные IPC/policy, проверка ACL/владельца/хэшей, Job Object, защищённый журнал. Старый worker есть только в test host. Production IPC/сеть проверены в CI; подробнее D-007.
- Случайные endpoints с auth SOCKS/probe/metrics; pure TUN без обычных прокси, combined сохраняет HTTP для WinInet. Общий HTTP без auth остаётся ограничением для локальных процессов. Метрики читаются HTTP, без statsquery subprocess.
- Опциональный persistent WFP kill switch для system/TUN: journal-before-arm, удержание блокировки при аварии/reconnect, явное снятие даже без ядра. По умолчанию выключен. Реальные WFP-фильтры и аварийное восстановление проверены в CI; D-010 содержит ограничения.
- Раздельный direct/VPN DNS, HTTPS-подписки с атомарным DPAPI-хранением, локальный QR, отдельные HTTPS-замеры профилей, перенос JSON через native host, добровольный ограниченный технический журнал без raw stderr/секретов.
- Парсер понимает дополнительные метаданные/HTTPUpgrade/REALITY, Hysteria2+Salamander, базовый KCP, userspace WireGuard JSON. Удалённый ядром H2, неработающий legacy KCP seed и отключение TLS-проверки отвергаются явно.
- Сериализация переходов, поколения и независимые cancel Events; поздние события не запускают новое соединение. Session/validator вынесены в session.py, dispatcher — именованные handlers. Подписки/замеры не держат lock состояния во время сети.
- Обновление/откат правил при активной сессии, immutable CDN fallback, закреплённый bundled RU snapshot с ru-blocked. Сборка не перезаписывает source runtime/core geodata.
- Независимый SHA256 Xray, ручная проверка обновлений, единая версия, production без test hooks. Release собирает/проверяет артефакт того же запуска, проверяет точный набор/хэши; Actions закреплены SHA.
- Setup содержит полный подписанный offline WebView2 x64; .NET 4.8 требуется заранее. Отдельная тестовая регистрация/mutex установщика не затрагивает активную установку пользователя.

## Исправления, найденные при живой приёмке

- Синхронный Windows named pipe блокировал запись при ожидающем чтении. Переведён на overlapped I/O с отдельными событиями/буферами и завершением отмены до освобождения handle. Настоящий pipe проверяет duplex, 256-КиБ кадр, cancel read/connect, лимит кадра и PID.
- Запускаемый native helper PowerShell не доходил до очистки TUN в CI. Очистка заменена `NetworkCleanup.cs`: точные IP Helper rows, только собственные маршруты/адреса; системный netsh сбрасывает DNS и отключает проверенный адаптер. Python независимо подтверждает восстановление.
- `RemoteProcess.poll` проверяет PID + время создания даже при живом IPC: умершее ядро с незавершённой очисткой больше не считается работающим. Новый helper восстанавливает stale lease того же живого backend, сохраняя чужого живого владельца.

## Проверки предыдущего выпуска (16 октября)

- Дерево предыдущего выпуска: `python -B -m unittest discover -s tests -v` — **222 теста, OK, exit 0**. Настоящий Xray, local DNS/игровой TCP/UDP, DPAPI/Планировщик/watchdog, native policy, WFP/IP Helper ABI и настоящий duplex pipe. Полный набор имеет внешние эффекты, описанные в testing.md; это не повторная проверка дерева после hotfix 27 октября.
- [Network acceptance](https://github.com/MaimeD666/Yukiwire-client/actions/runs/38889421618), ревизия `a9308c7c007104539500677802e74c6354ab2dd8`: защищённая установка/ACL/хэши, production IPC/prepare/stop/stale serial/EOF; настоящий system, pure TUN и combined; HTTPS с ростом счётчиков соответствующего inbound; снимки proxy/чужой сети восстановлены.
- В той же приёмке: настоящий WFP для system/combined, прямой TCP заблокирован, после аварии ядра/помощника блокировка сохранена; DNS UDP проверяет реальные ответы и уже открытый socket; явное release/recovery возвращает сеть, журналы удаляются. Разрыв IPC очищает собственный TUN. IPv6 DNS **SKIP**: у VM нет рабочей IPv6-базы; не выдавать проверку ABI за IPv6-трафик.
- [Release workflow](https://github.com/MaimeD666/Yukiwire-client/actions/runs/38889909332), ревизия `81510fd6`: все этапы прошли. Build/Checks: 222 теста после загрузки Xray; production без test hooks; UI (8 размеров/DPI, обе темы, формы/QR/диагностика); native/browser/helper crash; portable с bundled Python 3.14.8; установка/обновление/удаление отдельной тестовой копии, сохранение private sentinel и точный payload. Первый прогон до загрузки Xray явно пропускает 12 интеграций, второй выполняет их.
- Тот же Release прошёл дополнительную сетевую приёмку **именно опубликованного ZIP** с bundled Python и production helper: TUN/system/combined, TCP/UDP DNS, core/helper crash, EOF и recovery. IPv6 DNS отмечен SKIP. После загрузки проверены точный набор, digest и размер каждого asset; публичные latest/tag/commit дополнительно сверены. ZIP — 63 945 757 байт, Setup — 262 479 649 байт (с offline WebView2). SHA256 опубликованы в SHA256SUMS.txt.

## Оставшиеся ограничения и приёмка

Не проверены интерактивное согласие/отмена UAC (на hosted VM UAC отключён), реальный IPv6 интернет, старые TCP-потоки, BFE restart/reboot, sleep/resume, перенос между Windows-аккаунтами, чистая offline-машина без WebView2 и длительное YouTube-видео с конкретным zapret. HTTP/TLS и счётчики доказывают сетевой путь, не воспроизведение видео.

Общий HTTP WinInet остаётся без auth ради совместимости Windows-прокси; SOCKS и служебные endpoints защищены. Собственные binaries не подписаны. Обновления устанавливаются вручную. Legacy TUN-журнал восстанавливается прежним клиентом; старые защищённые версии автоматически не удаляются. Не описывать эти границы как «аудит полностью закрыт».

## Следующий конкретный шаг

Установить проверенный v0.6 вручную после отключения старого клиента; импортировать hy2/hysteria2-ссылку и проверить реальный сервер в удобное для пользователя окно. Длительное видео, переключение между разными удалёнными портами, IPv6 и остальные перечисленные ограничения остаются отдельными сценариями. Повторный независимый аудит main/v0.6 — будущая задача, не выполненная в этом выпуске.
