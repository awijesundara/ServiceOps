"""Localization readiness must fail visibly on omissions or unreadable source."""
import json
from pathlib import Path

import pytest

from tools.check_localization_coverage import coverage
from tools.localization_inventory import inventory


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_inventory_finds_hidden_help_errors_and_settings_without_record_values(tmp_path):
    (tmp_path / "templates").mkdir()
    (tmp_path / "static").mkdir()
    (tmp_path / "serviceops_core").mkdir()
    (tmp_path / "templates/page.html").write_text('''<h1>Service health</h1>
      <input title="Explain this setting" placeholder="Choose a receiver">
      <form data-confirm="Remove this destination?"><button>Remove</button></form>
      <p>{{ ticket.description }}</p><p>{{ t('Save') }}</p>
      <script>const secret = "Not an HTML label";</script>''', encoding="utf-8")
    (tmp_path / "app.py").write_text('''def route():
    flash("Destination saved.")
    abort(400, description="Select a valid transport.")
    fields = {"label": "Syslog transport"}
''', encoding="utf-8")
    (tmp_path / "static/page.js").write_text('button.textContent = "Try again";', encoding="utf-8")
    result = inventory(tmp_path)
    assert not result["errors"]
    messages = {entry["message"] for entry in result["messages"]}
    assert {"Service health", "Explain this setting", "Choose a receiver", "Remove this destination?", "Remove", "Save", "Destination saved.", "Select a valid transport.", "Syslog transport", "Try again"} <= messages
    assert "ticket.description" not in messages and "Not an HTML label" not in messages


def test_invalid_template_is_reported_instead_of_claiming_complete_inventory(tmp_path):
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates/broken.html").write_text("{% if %}broken{% endif %}", encoding="utf-8")
    (tmp_path / "app.py").write_text("", encoding="utf-8")
    result = inventory(tmp_path)
    assert result["errors"] == [{"path": "templates/broken.html", "error": "TemplateSyntaxError"}]


def test_coverage_reports_missing_and_blank_translation_entries(tmp_path):
    source = write_json(tmp_path / "inventory.json", {"messages": [{"message": "Save"}, {"message": "Cancel"}, {"message": "Try again"}], "errors": []})
    catalogs = write_json(tmp_path / "catalogs.json", {"ja": {"messages": {"Save": "保存", "Cancel": " "}}})
    result = coverage(source, catalogs, "ja")[0]
    assert result["present"] == 1 and result["missing"] == ["Cancel", "Try again"]
    assert result["complete"] is False


@pytest.mark.parametrize("document", [{"messages": [], "errors": []}, {"messages": [{"message": "Save"}], "errors": [{"error": "Unreadable source"}]}, {"messages": [{"message": None}]}])
def test_empty_or_incomplete_inventory_cannot_prove_complete_coverage(tmp_path, document):
    source = write_json(tmp_path / "inventory.json", document)
    catalogs = write_json(tmp_path / "catalogs.json", {"ja": {"messages": {"Save": "保存"}}})
    with pytest.raises(ValueError):
        coverage(source, catalogs)


def test_io_failure_and_unknown_language_are_explicit_errors(tmp_path):
    source = write_json(tmp_path / "inventory.json", {"messages": [{"message": "Save"}], "errors": []})
    catalogs = write_json(tmp_path / "catalogs.json", {"ja": {"messages": {"Save": "保存"}}})
    with pytest.raises(ValueError, match="Unknown language"):
        coverage(source, catalogs, "unknown")
    with pytest.raises(OSError):
        coverage(Path("/nonexistent/localization-inventory.json"), catalogs)


@pytest.mark.parametrize("translated", ["チケット {wrong}", "チケット", "{number.password}", "{number!r}"])
def test_full_entry_count_does_not_hide_broken_dynamic_messages(tmp_path, translated):
    source = write_json(tmp_path / "inventory.json", {"messages": [{"message": "Ticket {number}"}], "errors": []})
    catalogs = write_json(tmp_path / "catalogs.json", {"ja": {"messages": {"Ticket {number}": translated}}})
    result = coverage(source, catalogs)[0]
    assert result["present"] == 1
    assert result["invalid_parameters"] == ["Ticket {number}"]
    assert result["complete"] is False
