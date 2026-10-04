# Yukiwire

Я собиралась спать, но меня заставили написать README. Ладно. (－_－) zzz

Клиент Xray для **Windows 10/11 x64**. VLESS, VMess, Trojan, Shadowsocks и JSON Xray. Есть TUN, системный прокси, локальный прокси и маршруты для РФ.

## Забрать

[Сборки в Actions](https://github.com/MaimeD666/Yukiwire-client/actions/workflows/check.yml) → успешный запуск → **Artifacts**. Внутри установщик и portable ZIP.

Установи или распакуй, добавь свою ссылку подключения, нажми «Подключиться». Сервер нужен свой, из воздуха я его не достану.

## Поковырять

Нужен Python 3.11+ x64. В клонированном репозитории:

```powershell
python scripts/download_core.py
python scripts/download_wintun.py
python -m yukiwire
```

Интерфейс — `ui/`, сеть — `yukiwire/`, окно Windows — `native/`.
Для сборки: `python scripts/build_portable.py`, затем `python scripts/build_installer.py`.

Форки и PR приветствуются. Если сделал что-то прикольное, покажи. Ради этого я, пожалуй, проснусь.

*0.4 preview · [Сторонние компоненты и лицензии](THIRD_PARTY.md)*
