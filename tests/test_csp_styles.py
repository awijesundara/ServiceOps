"""Content-Security-Policy hardening: style-src carries no 'unsafe-inline'."""
import re
from pathlib import Path

from app import PlatformSetting, css_color, db, pct
from tests.test_app import app, client, login  # noqa: F401 - pytest fixtures

ROOT = Path(__file__).resolve().parents[1]


def style_src(response):
    csp = response.headers["Content-Security-Policy"]
    return next(part.strip() for part in csp.split(";") if part.strip().startswith("style-src"))


def test_style_src_has_no_unsafe_inline_and_every_style_block_carries_the_nonce(client):
    login(client)
    response = client.get("/")
    directive = style_src(response)
    assert "'unsafe-inline'" not in directive and "'unsafe-hashes'" not in directive
    nonce = re.search(r"'nonce-([A-Za-z0-9_-]+)'", directive).group(1)
    html = response.get_data(as_text=True)
    blocks = re.findall(r"<style([^>]*)>", html)
    assert blocks and all(f'nonce="{nonce}"' in attrs for attrs in blocks)
    assert not re.search(r'<[a-zA-Z][^>]*\sstyle="', html), "inline style attribute would be blocked"


def test_nonce_changes_per_response_and_pages_without_style_blocks_get_none(client):
    login(client)
    first, second = style_src(client.get("/")), style_src(client.get("/"))
    assert first != second
    assert style_src(client.get("/api/v1/docs")) == "style-src 'self'"


def test_no_template_ships_an_inline_style_attribute_or_unnonced_style_block():
    offenders = []
    for path in sorted((ROOT / "templates").glob("*.html")):
        content = path.read_text(encoding="utf-8")
        if re.search(r'<[a-zA-Z][^<>]*\sstyle="', content):
            offenders.append(f"{path.name}: style attribute")
        if re.search(r"<style(?![^>]*nonce=)", content):
            offenders.append(f"{path.name}: <style> without nonce")
    assert offenders == []


def test_brand_colors_cannot_inject_css_through_the_style_block(client, app):
    login(client)
    with app.app_context():
        db.session.add(PlatformSetting(key="BRAND_TEAL", value="red}body{display:none", encrypted=False))
        db.session.commit()
    html = client.get("/").get_data(as_text=True)
    assert "display:none" not in html
    assert ":root{--brand-primary:#003e4c;" in html


def test_css_color_and_pct_helpers():
    assert css_color("#12ab9f", "x") == "#12ab9f"
    assert css_color("rgb(1, 2, 3)", "x") == "rgb(1, 2, 3)"
    assert css_color("teal", "x") == "teal"
    for hostile in ("red;background:url(//x)", "red}a{b:c", "#fff</style><script>", "", None):
        assert css_color(hostile, "fallback") == "fallback"
    assert (pct(None), pct("x"), pct(-5), pct(42.6), pct(250)) == (0, 0, 0, 43, 100)

