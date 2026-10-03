"""Offline dynamic messages preserve supplied values and reject object traversal."""
from types import MappingProxyType

import pytest

from serviceops_core import localization
from tools.check_localization_coverage import parameter_names


def test_named_parameters_are_reordered_without_translating_record_values(monkeypatch):
    monkeypatch.setattr(localization, "CATALOGS", {
        "en": {"messages": {}},
        "ja": {"messages": {"Ticket {number}: {status}": "{status}：チケット {number}"}},
    })
    assert localization.translate("Ticket {number}: {status}", "ja", number="INC000001", status="User text") == "User text：チケット INC000001"


def test_bad_translation_falls_back_to_formatted_source_and_logs(monkeypatch, caplog):
    monkeypatch.setattr(localization, "CATALOGS", MappingProxyType({
        "en": {"messages": {}}, "ja": {"messages": {"Ticket {number}": "チケット {wrong}"}},
    }))
    assert localization.translate("Ticket {number}", "ja", number="INC000001") == "Ticket INC000001"
    assert "parameter mismatch" in caplog.text
    assert "INC000001" not in caplog.text


@pytest.mark.parametrize("message", ["{user.password}", "{user[password]}", "{}", "{value!r}", "{value:>10}", "{broken"])
def test_unsupported_parameter_syntax_is_rejected(message):
    with pytest.raises(ValueError):
        localization.message_parameters(message)
    with pytest.raises(ValueError):
        parameter_names(message)


def test_extra_or_missing_values_are_explicit_errors():
    with pytest.raises(ValueError):
        localization.translate("Ticket {number}", number="INC000001", extra="secret")
    with pytest.raises(ValueError):
        localization.translate("Ticket {number} {status}", number="INC000001")


def test_literal_braces_and_repeated_fields_are_preserved():
    assert localization.translate("{{{number}}}: {number}", number="INC000001") == "{INC000001}: INC000001"
