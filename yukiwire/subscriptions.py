"""Explicit HTTPS subscription downloads. URLs/contents never enter diagnostics."""
import base64
import http.client
import ssl
from urllib.parse import urlsplit, urljoin

from .config import build_config
from .version import USER_AGENT

LIMIT = 4 * 1024 * 1024
SCHEMES = ('vless://', 'vmess://', 'trojan://', 'ss://', 'hy2://', 'hysteria2://')


def validate_url(value):
    if not isinstance(value, str) or len(value) > 4096 or any(ord(char) < 33 for char in value):
        raise ValueError('Некорректный адрес подписки.')
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('Для подписки нужен HTTPS-адрес без логина/пароля в URL.')
    try:
        if parsed.port is not None and not 0 < parsed.port < 65536:
            raise ValueError()
    except ValueError:
        raise ValueError('Некорректный порт подписки.') from None
    return parsed


def download(url, proxy_port=None):
    try:
        for _ in range(4):
            parsed = validate_url(url)
            port = parsed.port or 443
            connection = http.client.HTTPSConnection('127.0.0.1' if proxy_port else parsed.hostname,
                                                     proxy_port or port, timeout=15, context=ssl.create_default_context())
            if proxy_port:
                connection.set_tunnel(parsed.hostname, port)
            try:
                path = parsed.path or '/'
                if parsed.query: path += '?' + parsed.query
                connection.request('GET', path, headers={'User-Agent': USER_AGENT, 'Accept': 'text/plain', 'Accept-Encoding': 'identity'})
                response = connection.getresponse()
                if response.status in (301, 302, 303, 307, 308):
                    url = urljoin(url, response.getheader('Location') or '')
                    validate_url(url)
                    continue
                if response.status != 200:
                    raise ValueError('Сервер подписки не вернул список профилей.')
                data = response.read(LIMIT + 1)
                if len(data) > LIMIT:
                    raise ValueError('Подписка больше 4 МиБ.')
                return data.decode('utf-8-sig')
            finally:
                connection.close()
        raise ValueError('Слишком много перенаправлений подписки.')
    except (OSError, http.client.HTTPException, UnicodeError):
        raise ValueError('Не удалось безопасно загрузить подписку. Проверьте ссылку и подключение.') from None


def profiles(text, validate):
    if not isinstance(text, str) or len(text) > LIMIT:
        raise ValueError('Некорректная подписка.')
    text = text.strip()
    if not text.startswith(SCHEMES):
        try:
            compact = ''.join(text.split())
            text = base64.b64decode(compact + '=' * (-len(compact) % 4), altchars=b'-_', validate=True).decode('utf-8-sig')
        except (ValueError, UnicodeError):
            raise ValueError('Подписка должна содержать ссылки профилей или их base64-список.') from None
    lines = list(dict.fromkeys(line.strip() for line in text.splitlines() if line.strip()))
    if not 1 <= len(lines) <= 100:
        raise ValueError('В подписке должно быть от 1 до 100 профилей.')
    result = []
    for line in lines:
        if not line.startswith(SCHEMES):
            raise ValueError('Подписка содержит неподдерживаемый тип профиля. Прежняя версия сохранена.')
        name, config = build_config(line)
        validate(config)
        result.append({'name': name, 'protocol': config['outbounds'][0]['protocol'], 'text': line})
    return result
