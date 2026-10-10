"""Account theme persistence and real browser selection regressions."""
import os
import re
import threading

import pytest
from werkzeug.serving import make_server

from app import User, UserPreference
from tests.test_app import app, client, login  # noqa: F401


@pytest.mark.parametrize('theme', ['navy', 'slate', 'forest'])
def test_professional_theme_persists_and_is_account_scoped(app, client, theme):
    login(client)
    response = client.post('/preferences', data={'theme': theme}, follow_redirects=True)
    assert response.status_code == 200
    assert b'Display and accessibility preferences saved.' in response.data
    with app.app_context():
        assert UserPreference.query.join(User).filter(User.username == 'admin').one().theme == theme
    home = client.get('/').data
    assert f'class="theme-{theme} density-'.encode() in home
    assert b'themes.css' in home and b'dark.css' not in home
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
            for theme, background in [('navy', 'rgb(243, 246, 250)'), ('slate', 'rgb(245, 246, 248)'), ('forest', 'rgb(245, 247, 243)')]:
                page.goto(base + '/preferences')
                radio = page.locator(f'input[name=theme][value={theme}]')
                radio.focus()
                radio.press('Space')
                expect(radio).to_be_checked()
                page.get_by_role('button', name='Save preferences', exact=True).click()
                page.wait_for_load_state('networkidle')
                expect(page.locator('body')).to_have_class(re.compile(f'theme-{theme}'))
                assert page.locator('body').evaluate('(el) => getComputedStyle(el).backgroundColor') == background
                assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
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
                assert contrast >= 4.5
                page.screenshot(path=f'/private/tmp/serviceops-theme-{theme}-{width}.png', full_page=True)
                page.reload()
                expect(page.locator(f'input[name=theme][value={theme}]')).to_be_checked()
            page.emulate_media(color_scheme='dark')
            page.locator('input[name=theme][value=system]').focus()
            page.locator('input[name=theme][value=system]').press('Space')
            page.get_by_role('button', name='Save preferences', exact=True).click()
            page.wait_for_load_state('networkidle')
            dark_background = page.locator('body').evaluate('(el) => getComputedStyle(el).backgroundColor')
            page.emulate_media(color_scheme='light')
            assert page.locator('body').evaluate('(el) => getComputedStyle(el).backgroundColor') != dark_background
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
