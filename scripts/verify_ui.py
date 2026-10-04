"""Exercise the real UI in Edge, with an isolated, in-memory backend fixture.

No saved profiles, system proxy, TUN or real connections are touched.
"""
from pathlib import Path
import json
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'runtime' / 'ui-checks'
PROFILE = 'vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls'


def emit(page, event, **fields):
    page.evaluate('(data)=>yukiwire.receive(data)', dict(event=event, **fields))


def open_page(page, name):
    page.locator(f'.sidebar [data-panel="{name}"]').click()
    expect(page.locator(f'.sidebar [data-panel="{name}"]')).to_have_attribute('aria-current', 'page')


def home(page):
    page.locator('button[data-page=home]').click()
    expect(page.locator('#home-view')).to_be_visible()


def capture(page, prefix, name):
    page.wait_for_timeout(220)
    page.screenshot(path=str(OUTPUT / f'{prefix}-{name}.png'))
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), f'{name}: horizontal overflow'
    assert page.evaluate('document.documentElement.scrollHeight <= innerHeight'), f'{name}: shell overflow'
    assert page.evaluate("document.querySelector('main').scrollWidth <= document.querySelector('main').clientWidth"), f'{name}: content overflow'


def connected(page):
    emit(page, 'started', capture='local')
    emit(page, 'probe_result', elapsed_ms=184)
    page.evaluate('''() => {
      for (let i=0; i<60; i++) yukiwire.receive({event:'telemetry', download_bytes:138127493,
        upload_bytes:13501324,download_bps:Math.max(0,Math.sin(i*.41)*500000+Math.sin(i*.15)*150000+250000),
        upload_bps:42000,uptime:924,reconnects:1,direct_bytes:501223});
    }''')
    emit(page, 'sites_result', results=[
        dict(target='chatgpt.com', transport_ok=True, accessible=False, http_status=403, elapsed_ms=284),
        dict(target='github.com', transport_ok=True, accessible=True, http_status=200, elapsed_ms=184)],
        exit={'profile': {'country': 'DE'}, 'chatgpt_route': {'country': 'DE'}})
    emit(page, 'analytics', total=dict(sessions=12, duration=18420, download_bytes=200000000,
         upload_bytes=18000000, direct_bytes=1000000, reconnects=2, failures=1, average_https_ms=200),
         recent=[dict(started=1790990000, duration=900, country='DE', download_bytes=10000000,
                      upload_bytes=1000000, interrupted=False)])


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    reports = []
    with sync_playwright() as engine:
        browser = engine.chromium.launch(channel='msedge', headless=True)
        for width, height, dpi in [(1120, 760, 1), (900, 760, 1.25), (1440, 940, 1.5), (800, 660, 1), (800, 620, 1), (1920, 1040, 1), (2560, 1400, 1.5), (500, 740, 1)]:
            context = browser.new_context(viewport={'width': width, 'height': height}, device_scale_factor=dpi)
            page = context.new_page()
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto((ROOT / 'ui/index.html').as_uri())
            page.wait_for_function('!!window.yukiwire')
            page.evaluate('''() => {
              window.commands = [];
              document.addEventListener('yukiwire-command', e => commands.push(e.detail));
            }''')
            prefix = f'{width}-{height}-{dpi}'

            # First-run guidance and a draft containing secrets survive navigation only in memory.
            emit(page, 'ready', profiles=[], settings={'capture': 'local'})
            expect(page.locator('#connect-button > span')).to_have_text('Добавить профиль')
            capture(page, prefix, 'empty')
            page.locator('#connect-button').click()
            page.locator('#edit-name').fill('Личный сервер')
            page.locator('#edit-profile').fill(PROFILE)
            expect(page.locator('#edit-profile')).to_have_css('-webkit-text-security', 'disc')
            page.locator('#show-secret').check()
            open_page(page, 'routing')
            open_page(page, 'profiles')
            expect(page.locator('#edit-profile')).to_have_value(PROFILE)
            expect(page.locator('#edit-name')).to_have_value('Личный сервер')
            expect(page.locator('#edit-profile')).to_have_css('-webkit-text-security', 'disc')
            assert PROFILE not in page.evaluate('JSON.stringify(localStorage)')
            page.locator('#save-profile').click()
            assert page.evaluate('commands.at(-1).action') == 'save_profile'
            expect(page.locator('#cancel-editor')).to_be_disabled()
            emit(page, 'error', operation='save_profile', message='Проверьте ссылку профиля')
            expect(page.locator('#profile-error')).to_be_visible()
            expect(page.locator('#save-profile')).to_be_enabled()
            expect(page.locator('#cancel-editor')).to_be_enabled()
            expect(page.locator('#temporary-connect')).to_be_enabled()
            page.locator('#temporary-connect').click()
            assert page.evaluate('commands.at(-1).profile') == PROFILE
            expect(page.locator('#connect-button > span')).to_have_text('Отменить')
            page.locator('#connect-button').click()
            assert page.evaluate('commands.at(-1).action') == 'stop'
            expect(page.locator('#connect-button')).to_be_disabled()
            emit(page, 'stopped')

            library = [dict(id='fixture', name='Домашний сервер', protocol='vless'),
                       dict(id='backup', name='Запасной сервер', protocol='trojan')]
            emit(page, 'ready', profiles=library, selected='fixture', settings={'capture': 'tun', 'preset': 'all'},
                 environment={'other_vpn': True})
            home(page)
            expect(page.locator('#home-capture')).to_have_value('tun')
            expect(page.locator('#connect-button')).to_be_disabled()
            emit(page, 'environment', environment={'other_vpn': False, 'other_proxy': False}, silent=True)
            expect(page.locator('#home-capture')).to_have_value('tun')
            expect(page.locator('#connect-button')).to_be_enabled()
            # Common actions stay on the overview; saving is serialized with connection start.
            emit(page, 'ready', profiles=library, selected='fixture', settings={'capture': 'local', 'preset': 'ru-direct'})
            home(page)
            page.locator('#home-profile').select_option('backup')
            page.locator('#home-preset').select_option('all')
            assert page.evaluate('commands.at(-1).settings.preset') == 'all'
            expect(page.locator('#connect-button')).to_be_disabled()
            expect(page.locator('#home-capture')).to_be_disabled()
            page.keyboard.press('Control+Enter')
            assert page.evaluate('commands.at(-1).action') == 'save_settings'
            emit(page, 'error', operation='save_settings', message='Тестовая ошибка сохранения')
            expect(page.locator('#home-preset')).to_have_value('ru-direct')
            expect(page.locator('#connect-button')).to_be_enabled()
            page.locator('#home-preset').select_option('all')
            emit(page, 'settings', settings=page.evaluate('commands.at(-1).settings'))
            assert page.evaluate('yukiwire.summary().panel') is None
            page.locator('#home-capture').select_option('system')
            emit(page, 'settings', settings=page.evaluate('commands.at(-1).settings'))
            page.locator('#connect-button').focus()
            page.keyboard.press('Control+Enter')
            assert page.evaluate('commands.at(-1).action') == 'start'
            assert page.evaluate('commands.at(-1).profile_id') == 'backup'
            assert page.evaluate('commands.at(-1).settings.capture') == 'system'
            expect(page.locator('#home-profile')).to_be_disabled()
            page.keyboard.press('Control+Enter')
            assert page.evaluate('commands.at(-1).action') == 'stop'
            emit(page, 'stopped')
            page.locator('#toast-close').click()
            if width >= 1500:
                page.locator('.home-profile-row').first.click()
                assert page.evaluate('commands.at(-1).action') == 'start'
                assert page.evaluate('commands.at(-1).profile_id') == 'fixture'
                page.locator('#connect-button').click()
                emit(page, 'stopped')

            # JSON keeps its original routing, regular profiles restore a usable preset.
            emit(page, 'profiles', profiles=library + [dict(id='json', name='JSON', protocol='JSON Xray')], selected='fixture')
            page.locator('#home-profile').select_option('json')
            expect(page.locator('#home-preset')).to_have_value('original')
            page.locator('#home-profile').select_option('fixture')
            expect(page.locator('#home-preset')).to_have_value('ru-direct')

            emit(page, 'ready', profiles=library, selected='fixture', settings={'capture': 'local', 'preset': 'ru-direct'},
                 environment={'other_proxy': True, 'other_vpn': True})
            assert page.locator('#home-capture option[value=tun]').evaluate('e=>e.disabled')
            assert page.locator('#home-capture option[value=system]').evaluate('e=>e.disabled')
            # Selecting a saved profile discards the temporary connection, but preserves editor drafts.
            open_page(page, 'profiles')
            page.locator('.profile-choice').first.click()
            capture(page, prefix, 'home')
            if width >= 800:
                assert page.evaluate("document.querySelector('main').scrollHeight <= document.querySelector('main').clientHeight + 1"), 'Overview requires scrolling'

            open_page(page, 'profiles')
            page.locator('#profile-search').fill('TROJAN')
            expect(page.locator('.profile-choice')).to_have_count(1)
            expect(page.locator('.profile-choice')).to_contain_text('Запасной')
            page.locator('#profile-search').fill('not-found')
            expect(page.locator('.empty-state')).to_contain_text('Ничего не нашлось')
            page.locator('#profile-search').fill('')
            page.locator('.delete-profile').last.click()
            expect(page.locator('#confirm-dialog')).to_be_visible()
            expect(page.locator('#confirm-cancel')).to_be_focused()
            for _ in range(5):
                page.keyboard.press('Tab')
                assert page.evaluate("!!document.activeElement.closest('#confirm-dialog')")
            page.keyboard.press('Escape')
            assert not page.evaluate("commands.some(x=>x.action === 'delete_profile')")
            page.locator('.delete-profile').last.click()
            page.locator('#confirm-delete').click()
            assert page.evaluate('commands.at(-1).profile_id') == 'backup'
            emit(page, 'profiles', profiles=library[:1], selected='fixture')
            page.locator('#add-profile').click()
            page.locator('#edit-profile').fill(PROFILE)
            capture(page, prefix, 'profiles')
            page.locator('#cancel-editor').click()
            expect(page.locator('#edit-profile')).to_have_value('')
            page.locator('.edit-profile').first.click()
            assert page.evaluate('commands.at(-1).action') == 'get_profile'
            emit(page, 'profile_detail', id='fixture', name=library[0]['name'], text=PROFILE)
            page.locator('#edit-name').fill('Основной сервер')
            page.locator('#save-profile').click()
            open_page(page, 'activity')
            library[0]['name'] = 'Основной сервер'
            emit(page, 'profiles', profiles=library[:1], selected='fixture')
            emit(page, 'saved', profile_id='fixture')
            assert page.evaluate('yukiwire.summary().panel') == 'activity'
            open_page(page, 'profiles')
            expect(page.locator('#profile-editor')).to_be_hidden()
            expect(page.locator('.profile-choice')).to_contain_text('Основной сервер')

            # Route drafts and validation errors, including a response after leaving the page.
            open_page(page, 'routing')
            page.locator('textarea[name=proxy]').fill('chatgpt.com\nopenai.com')
            open_page(page, 'settings')
            assert page.locator('select[name=capture] option[value=tun]').evaluate('e=>e.disabled')
            assert page.locator('select[name=capture] option[value=system]').evaluate('e=>e.disabled')
            # Background scans update availability without toasts, lost drafts or mode changes.
            page.locator('select[name=dns]').select_option('doh')
            page.evaluate("document.getElementById('toast').hidden=true")
            emit(page, 'environment', environment={'other_proxy': False, 'other_vpn': False}, silent=True)
            assert not page.locator('select[name=capture] option[value=tun]').evaluate('e=>e.disabled')
            page.locator('select[name=capture]').select_option('tun')
            emit(page, 'environment', environment={'other_proxy': False, 'other_vpn': True}, silent=True)
            expect(page.locator('select[name=capture]')).to_have_value('tun')
            expect(page.locator('select[name=dns]')).to_have_value('doh')
            expect(page.locator('#toast')).to_be_hidden()
            home(page)
            expect(page.locator('#environment-notice')).to_have_text('Другой VPN')
            emit(page, 'environment', environment={'other_proxy': False, 'other_vpn': False}, silent=True)
            expect(page.locator('#environment-notice')).to_be_hidden()
            assert not page.locator('#home-capture option[value=tun]').evaluate('e=>e.disabled')
            emit(page, 'environment', environment={'check_failed': True}, silent=True)
            expect(page.locator('#environment-notice')).to_have_text('Сеть не проверена')
            emit(page, 'environment', environment={'other_proxy': True, 'other_vpn': False}, silent=True)
            expect(page.locator('#environment-notice')).to_have_text('Другой прокси')
            open_page(page, 'settings')
            page.locator('select[name=capture]').select_option('local')
            page.evaluate("Object.defineProperty(navigator.clipboard, 'writeText', {value: async text => {window.copiedAddress=text}})")
            page.locator('#settings-form [data-copy="127.0.0.1:11809"]').click()
            assert page.evaluate('window.copiedAddress') == '127.0.0.1:11809'
            page.locator('select[name=dns]').select_option('doh')
            open_page(page, 'routing')
            expect(page.locator('textarea[name=proxy]')).to_have_value('chatgpt.com\nopenai.com')
            page.locator('#routing-form button[type=submit]').click()
            assert page.evaluate('commands.at(-1).settings.proxy') == 'chatgpt.com\nopenai.com'
            expect(page.locator('#routing-form button[type=submit]')).to_be_disabled()
            emit(page, 'error', operation='save_settings', message='Тестовая ошибка маршрута')
            expect(page.locator('#routing-error')).to_be_visible()
            expect(page.locator('#routing-form button[type=submit]')).to_be_enabled()
            page.locator('#routing-form button[type=submit]').click()
            saved_settings = page.evaluate('commands.at(-1).settings')
            open_page(page, 'settings')
            emit(page, 'settings', settings=saved_settings)
            assert page.evaluate('yukiwire.summary().panel') == 'settings'
            expect(page.locator('select[name=dns]')).to_have_value('doh')
            page.locator('#settings-form button[type=submit]').click()
            emit(page, 'settings', settings=page.evaluate('commands.at(-1).settings'))
            expect(page.locator('#settings-form button[type=submit]')).to_be_disabled()
            capture(page, prefix, 'settings')
            open_page(page, 'routing')
            expect(page.locator('textarea[name=proxy]')).to_have_value('chatgpt.com\nopenai.com')
            capture(page, prefix, 'routing')
            # Shared controls must align in real pixels, including Windows scaling.
            field = page.locator('#explain-target').bounding_box()
            button = page.locator('#explain-form button').bounding_box()
            assert abs(field['height'] - button['height']) < 1, (field, button)
            assert abs(field['y'] - button['y']) < 1, (field, button)

            # Connection can change from the tray while a form remains open.
            connected(page)
            expect(page.locator('textarea[name=proxy]')).to_be_disabled()
            expect(page.locator('#locked-notice')).to_be_visible()
            page.locator('#unlock-settings').click()
            assert page.evaluate('commands.at(-1).action') == 'stop'
            emit(page, 'stopped')
            expect(page.locator('textarea[name=proxy]')).to_be_enabled()
            home(page)
            connected(page)
            expect(page.locator('#browser-button')).to_be_visible()
            expect(page.locator('#connection-title')).to_have_text('Прокси готов')
            capture(page, prefix, 'connected')
            assert page.locator('#connect-button').bounding_box()['height'] > page.locator('#check-button').bounding_box()['height'] * 1.5
            if width >= 800:
                assert page.evaluate("document.querySelector('main').scrollHeight <= document.querySelector('main').clientHeight + 1"), 'Connected overview requires scrolling'
                assert page.locator('.health-card').evaluate('e=>e.scrollHeight <= e.clientHeight + 1'), 'Overview actions clipped inside health card'
            old_chart = page.locator('#chart-down').get_attribute('d')
            open_page(page, 'activity')
            emit(page, 'telemetry', download_bps=100000, upload_bps=1000, uptime=925)
            page.wait_for_timeout(50)
            assert page.locator('#chart-down').get_attribute('d') == old_chart, 'Hidden chart was redrawn'
            home(page)
            page.wait_for_timeout(50)
            assert page.locator('#chart-down').get_attribute('d') != old_chart, 'Chart did not catch up on return'
            page.locator('#browser-button').click()
            assert page.evaluate('commands.at(-1).action') == 'open_browser'
            page.locator('#check-button').click()
            assert page.evaluate('commands.at(-1).action') == 'check_sites'
            assert page.evaluate('yukiwire.summary().panel') is None
            expect(page.locator('#check-button')).to_be_disabled()
            open_page(page, 'activity')
            expect(page.locator('#activity-check')).to_be_disabled()
            emit(page, 'sites_result', results=[dict(target='chatgpt.com', transport_ok=True,
                 accessible=False, http_status=403, elapsed_ms=284)], exit={'profile': {'country': 'DE'}})
            expect(page.locator('.site-row').first).to_contain_text('HTTPS работает')
            expect(page.locator('.site-row').first).to_contain_text('Сайт: 403')
            capture(page, prefix, 'activity')
            page.locator('[data-activity-tab=history]').click()
            expect(page.locator('#analytics-box')).to_be_visible()
            capture(page, prefix, 'history')

            home(page)
            page.locator('#theme-toggle').click()
            expect(page.locator('html')).to_have_attribute('data-theme', 'light')
            capture(page, prefix, 'light')
            open_page(page, 'settings')
            page.locator('#reduce-motion').check()
            assert page.locator('body').evaluate("e=>e.classList.contains('reduce-motion')")
            capture(page, prefix, 'settings-light')
            page.keyboard.press('Alt+1')
            expect(page.locator('#home-view')).to_be_visible()
            page.keyboard.press('Alt+2')
            expect(page.locator('#profile-search')).to_be_visible()

            emit(page, 'stopped')
            emit(page, 'probe_result', elapsed_ms=120)
            assert page.evaluate('yukiwire.summary().phase') == 'idle', 'Stale probe must not reconnect UI'
            emit(page, 'profiles', profiles=[dict(id='xss', name='<img src=x onerror=alert(1)>', protocol='vless')], selected='xss')
            assert page.locator('#home-profile img').count() == 0
            assert page.locator('#profile-list img').count() == 0
            home(page)
            emit(page, 'service_exited')
            expect(page.locator('#connect-button')).to_be_disabled()
            expect(page.locator('#connection-title')).to_have_text('Сервис недоступен')
            capture(page, prefix, 'service-error')
            page.reload()
            expect(page.locator('html')).to_have_attribute('data-theme', 'light')
            assert page.locator('body').evaluate("e=>e.classList.contains('reduce-motion')")
            assert not errors, errors
            reports.append(dict(width=width, height=height, dpi=dpi, passed=True))
            print(f'Navigation, drafts, secrets, forms, deletion, connection lifecycle, themes, layout: {prefix} passed')
            context.close()
        browser.close()
    (OUTPUT / 'report.json').write_text(json.dumps(reports, indent=2))


if __name__ == '__main__':
    main()
