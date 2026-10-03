"""Bundled offline UI catalogs: no provider, network calls or user-content translation."""
import json
import logging
from pathlib import Path
from string import Formatter
from types import MappingProxyType

logger = logging.getLogger(__name__)
RTL_LANGUAGES = frozenset({"ar", "fa", "he", "ur", "ps"})


def _load_catalogs():
    try:
        raw = json.loads(Path(__file__).with_name("locales").joinpath("catalogs.json").read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or "en" not in raw:
            raise ValueError("English catalog is required")
        catalogs = {}
        for code, entry in raw.items():
            if not isinstance(code, str) or not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                raise ValueError("Invalid language catalog metadata")
            messages = entry.get("messages")
            if not isinstance(messages, dict) or not all(isinstance(key, str) and isinstance(value, str) and value for key, value in messages.items()):
                raise ValueError("Invalid language catalog messages")
            catalogs[code] = MappingProxyType({"name": entry["name"], "messages": MappingProxyType(messages)})
        return MappingProxyType(catalogs)
    except (OSError, UnicodeError, ValueError, TypeError):
        logger.exception("Offline language catalogs could not be loaded; using English")
        return MappingProxyType({"en": MappingProxyType({"name": "English", "messages": MappingProxyType({})})})


CATALOGS = _load_catalogs()
LANGUAGE_OPTIONS = tuple((code, entry["name"]) for code, entry in CATALOGS.items())


def valid_language(code):
    return isinstance(code, str) and code in CATALOGS


def message_parameters(message):
    """Accept named values only, without object traversal or format conversions."""
    try:
        names = set()
        for _, name, specification, conversion in Formatter().parse(message):
            if name is None:
                continue
            if not name.isidentifier() or specification or conversion:
                raise ValueError("Translation parameters must be simple named fields")
            names.add(name)
        return frozenset(names)
    except (TypeError, ValueError):
        logger.exception("Invalid offline translation parameter syntax")
        raise


def translate(message, language="en", **parameters):
    try:
        catalog = CATALOGS.get(language, CATALOGS["en"])
        translated = catalog["messages"].get(message, message)
        if not parameters:
            return translated
        expected = message_parameters(message)
        if expected != set(parameters):
            raise ValueError("Translation parameter names do not match the source message")
        if message_parameters(translated) != expected:
            logger.error("Offline translation parameter mismatch for language %s; using source message", language)
            translated = message
        return translated.format_map(parameters)
    except (TypeError, ValueError, KeyError):
        logger.exception("Offline message formatting failed for language %s", language)
        raise


def template_context(language="en"):
    language = language if valid_language(language) else "en"
    return {
        "ui_language": language,
        "ui_direction": "rtl" if language in RTL_LANGUAGES else "ltr",
        "language_options": LANGUAGE_OPTIONS,
        "t": lambda message, **parameters: translate(message, language, **parameters),
    }
