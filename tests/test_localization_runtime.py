"""Interface localization: source coverage gates, catalog integrity, safe
rendering, language resolution and right-to-left layout."""
import json
import sys
from datetime import datetime
from pathlib import Path
from types import MappingProxyType

import pytest
from markupsafe import Markup

from app import PlatformSetting, UserPreference, db
from serviceops_core import localization
from tests.test_app import app, client, login  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import i18n_build_catalogs  # noqa: E402
import i18n_interface_values  # noqa: E402
import i18n_wrap_templates  # noqa: E402


def test_every_template_string_is_routed_through_tr():
    """New interface text must be wrapped; the migration tool finds none left."""
    leftovers = []
    for path in [*sorted((ROOT / "templates").rglob("*.html")), *sorted((ROOT / "installer/templates").rglob("*.html"))]:
        rewriter = i18n_wrap_templates.Rewriter(path.read_text(encoding="utf-8"), str(path.relative_to(ROOT)))
        rewriter.result()
        leftovers.extend(f"{rewriter.name}: {row['message']}" for row in rewriter.messages)
    assert leftovers == []


def test_extracted_source_messages_are_current():
    found, errors = i18n_build_catalogs.extract(ROOT)
    assert errors == []
    committed = json.loads((ROOT / "serviceops_core/locales/source.json").read_text(encoding="utf-8"))["messages"]
    expected = [{"id": message, "javascript": True} if entry["javascript"] else {"id": message}
                for message, entry in sorted(found.items())]
    assert committed == expected, "run tools/i18n_build_catalogs.py extract"


def test_interface_value_registry_is_current():
    current = (ROOT / "serviceops_core/interface_values.py").read_text(encoding="utf-8")
    assert current == i18n_interface_values.render(i18n_interface_values.harvest(ROOT)), \
        "run tools/i18n_interface_values.py"


def test_every_bundled_catalog_loads_and_passes_quality_checks():
    index = json.loads((ROOT / "serviceops_core/locales/index.json").read_text(encoding="utf-8"))
    languages = index["languages"]
    assert set(localization.LANGUAGES) == set(languages)
    assert {"en", "ar", "he", "fa", "ur", "zh-Hans", "zh-Hant", "si", "ta", "hi", "ja"} <= set(languages)
    files = {path.stem for path in (ROOT / "serviceops_core/locales/messages").glob("*.json")}
    assert files == set(languages) - {"en"}
    for code in files:
        document = json.loads((ROOT / "serviceops_core/locales/messages" / f"{code}.json").read_text(encoding="utf-8"))
        script = languages[code]["script"]
        for source, translated in document["messages"].items():
            assert source in localization.SOURCE_MESSAGES, (code, source)
            assert i18n_build_catalogs.check_translation(source, translated, script) is None, (code, source)
        assert localization.CATALOGS[code]["messages"] == document["messages"]


@pytest.mark.parametrize("code,direction", [("ar", "rtl"), ("he", "rtl"), ("fa", "rtl"), ("ur", "rtl"), ("ps", "rtl"),
                                            ("si", "ltr"), ("ja", "ltr"), ("en", "ltr")])
def test_direction_follows_the_writing_system(code, direction):
    assert localization.LANGUAGES[code]["direction"] == direction


def test_translations_are_escaped_and_only_markup_parameters_stay_raw(monkeypatch):
    monkeypatch.setattr(localization, "CATALOGS", {
        "en": {"messages": {}},
        "ja": {"messages": {"Open {name}": "<script>x</script>{name} を開く", "Save": "<b>保存</b>"}},
    })
    rendered = localization.translate_markup("Open {name}", "ja", name="<img src=x>")
    assert "<script>" not in rendered and "<img" not in rendered and "&lt;script&gt;" in rendered
    assert localization.translate_markup("Open {name}", "ja", name=Markup("<em>icon</em>")).endswith("<em>icon</em> を開く")
    assert localization.translate_markup("Save", "ja") == Markup("&lt;b&gt;保存&lt;/b&gt;")


def test_malformed_translation_falls_back_to_english(monkeypatch, caplog):
    monkeypatch.setattr(localization, "CATALOGS", {"en": {"messages": {}}, "ja": {"messages": {"Ticket {number}": "{broken"}}})
    assert localization.translate("Ticket {number}", "ja", number="INC1") == "Ticket INC1"
    assert "parameter mismatch" in caplog.text


def test_fallback_chain_uses_the_parent_language(monkeypatch):
    monkeypatch.setattr(localization, "LANGUAGES", MappingProxyType({
        **localization.LANGUAGES,
        "pt-BR": MappingProxyType({**localization.LANGUAGES["pt-BR"], "fallback": "pt"}),
    }))
    monkeypatch.setattr(localization, "CATALOGS", {"en": {"messages": {}}, "pt": {"messages": {"Save": "Salvar"}},
                                                   "pt-BR": {"messages": {"Cancel": "Cancelar"}}})
    assert localization.translate("Save", "pt-BR") == "Salvar"
    assert localization.translate("Cancel", "pt-BR") == "Cancelar"
    assert localization.translate("Unknown text", "pt-BR") == "Unknown text"


@pytest.mark.parametrize("header,expected", [
    ("fr-CH, fr;q=0.9, en;q=0.8", "fr"),
    ("zh-TW,zh;q=0.9", "zh-Hant"),
    ("zh-CN", "zh-Hans"),
    ("no", "nb"),
    ("pt-PT", "pt"),
    ("en-GB;q=0.5, si-LK;q=0.9", "si"),
    ("xx-YY, *;q=0.1", None),
    ("de;q=0", None),
    ("", None),
])
def test_accept_language_negotiation(header, expected):
    assert localization.negotiate(header) == expected


def test_resolution_order_preference_browser_default(monkeypatch):
    monkeypatch.setattr(localization, "_default_language", lambda: "ja")
    assert localization.resolve_language("si", "fr", api_request=False) == "si"
    assert localization.resolve_language("auto", "fr", api_request=False) == "fr"
    assert localization.resolve_language("auto", "", api_request=False) == "ja"
    assert localization.resolve_language(None, "fr", api_request=True) == "en"
    assert localization.resolve_language(None, "fr", api_request=False) == "fr"


def test_interface_values_translate_but_record_content_does_not(monkeypatch):
    monkeypatch.setattr(localization, "CATALOGS", {"en": {"messages": {}}, "de": {"messages": {"In Progress": "In Bearbeitung"}}})
    assert localization.translate_value("In Progress", "de") == "In Bearbeitung"
    assert localization.translate_value("Printer jams on page 3", "de") == "Printer jams on page 3"
    assert localization.translate_value(None, "de") is None
    assert localization.translate_value(42, "de") == 42


def test_plural_selection_uses_the_count():
    assert localization.translate_plural(1, "{count} device", "{count} devices") == "1 device"
    assert localization.translate_plural(3, "{count} device", "{count} devices") == "3 devices"


def test_calendar_names_come_from_cldr():
    moment = datetime(2026, 10, 4, 9, 30)
    assert localization.localized_strftime(moment, "%b %d, %H:%M", "en") == "Oct 04, 09:30"
    french = localization.localized_strftime(moment, "%B %d", "fr")
    assert french.startswith("octobre"), french
    assert localization.localized_strftime(moment, "%A", "ja") == "日曜日"


def test_language_picker_lists_every_language_with_its_own_name():
    options = dict(localization.language_options())
    assert set(options) == set(localization.LANGUAGES)
    assert options["si"].startswith("සිංහල — Sinhala")
    assert options["ar"].startswith("العربية — Arabic")
    assert options["en"] == "English"


def test_arabic_page_is_right_to_left_with_translated_catalog(app, client):
    login(client)
    assert client.post("/preferences", data={"language": "ar", "font_scale": "100"}).status_code == 302
    page = client.get("/preferences").get_data(as_text=True)
    assert 'lang="ar" dir="rtl"' in page
    assert "/static/rtl.css" in page and "/static/i18n.js" in page
    catalog = page.split('id="serviceops-i18n">', 1)[1].split("</script>", 1)[0]
    assert isinstance(json.loads(catalog), dict)


def test_english_page_embeds_an_empty_script_catalog(app, client):
    login(client)
    page = client.get("/preferences").get_data(as_text=True)
    assert 'id="serviceops-i18n">{}</script>' in page
    assert 'lang="en" dir="ltr"' in page


def test_automatic_preference_follows_the_browser(app, client):
    login(client)
    assert client.post("/preferences", data={"language": "auto", "font_scale": "100"}).status_code == 302
    with app.app_context():
        assert UserPreference.query.filter_by(user_id=1).one().language == "auto"
    page = client.get("/preferences", headers={"Accept-Language": "ja-JP,ja;q=0.9"}).get_data(as_text=True)
    assert 'lang="ja" dir="ltr"' in page


@pytest.mark.parametrize("value", ["../en", "xx", "en;drop", ""])
def test_unknown_language_is_rejected(app, client, value):
    login(client)
    assert client.post("/preferences", data={"language": value, "font_scale": "100"}).status_code == 400


def test_signed_out_pages_follow_the_browser_then_the_instance_default(app, client):
    page = client.get("/login", headers={"Accept-Language": "he"}).get_data(as_text=True)
    assert 'lang="he" dir="rtl"' in page
    with app.app_context():
        db.session.merge(PlatformSetting(key="DEFAULT_LANGUAGE", value="si"))
        db.session.commit()
    page = client.get("/login").get_data(as_text=True)
    assert 'lang="si" dir="ltr"' in page


def test_installer_follows_the_browser_language():
    from installer.app import create_app as create_installer
    installer = create_installer()
    page = installer.test_client().get("/", headers={"Accept-Language": "ar"}).get_data(as_text=True)
    assert 'lang="ar" dir="rtl"' in page and 'id="serviceops-i18n"' in page
    with installer.test_request_context("/api/validate", headers={"Accept-Language": "ar"}):
        assert localization.request_language() == "ar"


def test_api_token_clients_keep_english_errors(app, client):
    response = client.get("/api/v1/tickets", headers={"Accept-Language": "fr"})
    assert response.status_code in {401, 403}
    with app.test_request_context("/api/v1/tickets", headers={"Accept-Language": "fr"}):
        assert localization.request_language() == "en"


def test_offline_translation_markers_round_trip_and_reject_damage(tmp_path):
    import i18n_translate_offline as offline
    protected, names = offline.protect("Assign {number} to {group}")
    assert protected == "Assign [0] to [1]" and names == ["number", "group"]
    assert offline.restore("Asignar [0] a [1]", names) == "Asignar {number} a {group}"
    assert offline.restore("Asignar [0] a [0]", names) is None
    assert offline.restore("Asignar a [1]", names) is None
    assert offline.restore("Asignar [0] a [1] [2]", names) is None
    assert offline.madlad_tag("zh-Hans") == "zh" and offline.madlad_tag("nb") == "no" and offline.madlad_tag("si") == "si"
    jsonl = tmp_path / "out.jsonl"
    jsonl.write_text(json.dumps({"language": "si", "source": "Save", "translation": "සුරකින්න"}, ensure_ascii=False) + "\n",
                     encoding="utf-8")
    assert offline.to_catalog_input(jsonl, tmp_path / "in.json") == {"si": 1}
    assert offline.done_pairs(jsonl) == {("si", "Save")}
