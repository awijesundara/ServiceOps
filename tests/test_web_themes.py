"""Account theme persistence and real browser selection regressions."""
import os
import re
import threading

import pytest
from werkzeug.serving import make_server

from app import DARK_THEMES, THEMES, User, UserPreference
from tests.test_app import app, client, login  # noqa: F401


@pytest.mark.parametrize('theme', ['navy', 'slate', 'forest', 'ocean', 'indigo', 'sandstone', 'graphite', 'midnight'])
def test_professional_theme_persists_and_is_account_scoped(app, client, theme):
    login(client)
    response = client.post('/preferences', data={'theme': theme}, follow_redirects=True)
    assert response.status_code == 200
    assert b'Display and accessibility preferences saved.' in response.data
    with app.app_context():
        assert UserPreference.query.join(User).filter(User.username == 'admin').one().theme == theme
    home = client.get('/').data
    assert f'class="theme-{theme} density-'.encode() in home
    assert b'themes.css' in home
    assert (b'dark.css' in home) == (theme in DARK_THEMES)
    assert (b'class="theme-dark' in home) == (theme in DARK_THEMES)
    client.post('/logout')
    login(client)
    assert f'class="theme-{theme} density-'.encode() in client.get('/').data
    client.post('/logout')
    login(client, 'employee', 'Employee123!')
    assert b'class="theme-light density-' in client.get('/').data


@pytest.mark.skipif(os.getenv('RUN_THEME_BROWSER') != '1', reason='Enable real browser checks with RUN_THEME_BROWSER=1')
@pytest.mark.parametrize('width', [1440, 390])
def test_theme_cards_keyboard_save_and_render(app, width):
    from playwright.sync_api import expect, sync_playwright

    app.config.update(CSRF_ENABLED=True, SESSION_COOKIE_SECURE=False)
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={'width': width, 'height': 1000})
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            base = f'http://127.0.0.1:{server.server_port}'
            page.goto(base + '/login')
            page.locator('[name=username]').fill('admin')
            page.locator('[name=password]').fill('Admin123!')
            page.locator('button.primary').click()
            page.wait_for_load_state('networkidle')
            page.goto(base + '/preferences')
            page.wait_for_load_state('networkidle')
            page.locator('input[name=theme][value=light]').focus()
            page.locator('input[name=theme][value=light]').press('ArrowRight')
            expect(page.locator('input[name=theme][value=navy]')).to_be_checked()
            expect(page.locator('body')).to_have_class(re.compile('theme-navy'))
            page.get_by_role('button', name='Reset preview', exact=True).click()
            page.locator('.theme-option:has(input[value=indigo])').click()
            expect(page.locator('body')).to_have_class(re.compile('theme-indigo'))
            page.get_by_role('button', name='Reset preview', exact=True).click()
            backgrounds = {
                'light': 'rgb(244, 247, 248)', 'navy': 'rgb(243, 246, 250)',
                'slate': 'rgb(245, 246, 248)', 'forest': 'rgb(245, 247, 243)',
                'ocean': 'rgb(241, 247, 249)', 'indigo': 'rgb(246, 245, 250)',
                'sandstone': 'rgb(248, 246, 242)', 'graphite': 'rgb(21, 25, 31)',
                'midnight': 'rgb(15, 24, 40)', 'dark': 'rgb(15, 21, 26)',
            }
            for theme in THEMES:
                radio = page.locator(f'input[name=theme][value={theme}]')
                radio.focus()
                radio.press('Space')
                expect(radio).to_be_checked()
                assert radio.evaluate('(el) => document.activeElement === el')
                assert radio.locator('..').evaluate('(el) => getComputedStyle(el).outlineStyle') != 'none'
                expect(page.locator('body')).to_have_class(re.compile(f'theme-{theme}'))
                if theme != 'system':
                    assert page.locator('body').evaluate('(el) => getComputedStyle(el).backgroundColor') == backgrounds[theme]
                with app.app_context():
                    assert UserPreference.query.join(User).filter(User.username == 'admin').one().theme == 'light'
                assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), page.evaluate("Array.from(document.querySelectorAll('body *')).filter(el => el.getBoundingClientRect().right > innerWidth + 1).map(el => [el.tagName, el.className, el.getBoundingClientRect().right]).slice(0, 15)")
                contrast = page.locator('.theme-option:has(input:checked) small').evaluate(r"""el => {
                    const luminance = color => {
                        const c = color.match(/[\d.]+/g).slice(0, 3).map(v => Number(v) / 255)
                          .map(v => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4);
                        return c[0] * .2126 + c[1] * .7152 + c[2] * .0722;
                    };
                    const a = luminance(getComputedStyle(el).color);
                    const b = luminance(getComputedStyle(el.closest('.theme-option')).backgroundColor);
                    return (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
                }""")
                assert contrast >= 4.5, (theme, contrast)
                page.locator('h1').click()
                page.evaluate('window.scrollTo(0, 0)')
                page.screenshot(path=f'/private/tmp/serviceops-preview-{theme}-{width}.png', full_page=True)
            page.get_by_role('button', name='Reset preview', exact=True).click()
            expect(page.locator('body')).to_have_class(re.compile('theme-light'))
            expect(page.locator('input[name=theme][value=light]')).to_be_checked()
            expect(page.locator('#theme-preview-status')).to_have_text('Showing your saved theme.')
            # Reload and ordinary navigation discard preview without writing any preference.
            page.locator('input[name=theme][value=midnight]').press('Space')
            page.reload()
            expect(page.locator('body')).to_have_class(re.compile('theme-light'))
            page.locator('input[name=theme][value=ocean]').press('Space')
            page.goto(base + '/')
            expect(page.locator('body')).to_have_class(re.compile('theme-light'))
            page.goto(base + '/preferences')
            page.locator('input[name=theme][value=midnight]').press('Space')
            page.get_by_role('button', name='Save preferences', exact=True).click()
            page.wait_for_load_state('networkidle')
            expect(page.locator('body')).to_have_class(re.compile('theme-midnight'))
            page.reload()
            expect(page.locator('input[name=theme][value=midnight]')).to_be_checked()
            with app.app_context():
                assert UserPreference.query.join(User).filter(User.username == 'admin').one().theme == 'midnight'
            # System preview follows OS changes immediately, before save, from a saved dark palette.
            page.emulate_media(color_scheme='dark')
            page.locator('input[name=theme][value=system]').press('Space')
            dark_background = page.locator('body').evaluate('(el) => getComputedStyle(el).backgroundColor')
            page.emulate_media(color_scheme='light')
            assert page.locator('body').evaluate('(el) => getComputedStyle(el).backgroundColor') != dark_background
            page.get_by_role('button', name='Reset preview', exact=True).click()
            expect(page.locator('body')).to_have_class(re.compile('theme-midnight'))
            # Account accessibility options survive previews and reset.
            page.locator('input[name=high_contrast]').press('Space')
            page.locator('input[name=reduced_motion]').press('Space')
            page.get_by_role('button', name='Save preferences', exact=True).click()
            page.wait_for_load_state('networkidle')
            for theme in ('indigo', 'graphite', 'system'):
                page.locator(f'input[name=theme][value={theme}]').press('Space')
                expect(page.locator('body')).to_have_class(re.compile('high-contrast'))
                expect(page.locator('body')).to_have_class(re.compile('reduced-motion'))
            page.get_by_role('button', name='Reset preview', exact=True).click()
            expect(page.locator('input[name=high_contrast]')).to_be_checked()
            page.locator('input[name=high_contrast]').press('Space')
            page.locator('input[name=reduced_motion]').press('Space')
            page.get_by_role('button', name='Save preferences', exact=True).click()
            page.wait_for_load_state('networkidle')
            # Exercise shared surfaces outside the picker, including maximum account font scale.
            with app.app_context():
                preference = UserPreference.query.join(User).filter(User.username == 'admin').one()
                preference.font_scale = 140
                from app import db
                db.session.commit()
            for theme in ('ocean', 'midnight'):
                page.goto(base + '/preferences')
                page.wait_for_load_state('networkidle')
                page.locator('input[name=theme][value=' + theme + ']').press('Space')
                page.get_by_role('button', name='Save preferences', exact=True).click()
                page.wait_for_load_state('networkidle')
                for path in ('/', '/tickets/incident', '/cmdb'):
                    response = page.goto(base + path)
                    assert response.status == 200
                    page.wait_for_load_state('networkidle')
                    expect(page.locator('body')).to_have_class(re.compile(f'theme-{theme}'))
                    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), (theme, path, width)
                    page.screenshot(path=f'/private/tmp/serviceops-workspace-{theme}-{width}-{path.strip("/").replace("/", "-") or "home"}.png', full_page=True)
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
