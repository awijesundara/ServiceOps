"""Shared source, generated output, override guard and safe component rendering."""
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from tools.build_interface_system import build, TARGET
from tools.check_interface_system import violations, overrides
from tests.test_app import app, client, login  # noqa: F401


def test_generated_contract_is_current():
    assert TARGET.read_text() == build()
    assert not violations()
    root = TARGET.parents[1]
    for source, target in [('calendar.js', 'calendar.js'), ('notice-cards.js', 'service-status-feed.js'), ('themes.css', 'themes.css')]:
        assert (root / 'design_system' / source).read_bytes() == (root / 'static' / target).read_bytes()


def test_override_guard_rejects_new_fixed_geometry():
    assert overrides('.dashboard-columns{gap:25px}')
    assert overrides('.page .ui-stack{margin-bottom:19px}')
    assert overrides('.new-page .primary { height:19px; padding:3px }')
    assert overrides('@media(max-width:700px){.new-page .button{font-size:9px}}')
    assert not overrides('.chart{height:200px}.primary{height:var(--control-height)}')
    assert not overrides('.button::before{height:12px}')


def test_macros_escape_text_and_default_to_non_submitting_controls():
    env = Environment(loader=FileSystemLoader(Path(__file__).resolve().parents[1] / 'templates'), autoescape=select_autoescape())
    macros = env.get_template('_ui.html').module
    html = str(macros.button('<script>bad</script>'))
    assert 'type="button"' in html and '&lt;script&gt;' in html
    assert 'disabled' in str(macros.button('Unavailable', href='/admin', disabled=True))
    assert '<a ' not in str(macros.button('Unavailable', href='/admin', disabled=True))


def test_reference_is_admin_only_and_discoverable(client, app):
    login(client, 'employee', 'Employee123!')
    assert client.get('/admin/interface-standards').status_code == 403
    with client.session_transaction() as session:
        session.clear()
    login(client, 'admin', 'Admin123!')
    response = client.get('/admin/interface-standards')
    assert response.status_code == 200
    assert b'aria-describedby="sample-error-error"' in response.data
    assert b'/admin/interface-standards' in client.get('/admin/section/platform-security').data
