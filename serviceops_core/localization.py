"""Offline interface localization.

Catalogs are bundled JSON files generated at build time (see
tools/i18n_build_catalogs.py); nothing is translated at runtime and no
translation provider or network service is ever called. The English source text
is the message identifier and the final fallback, so a missing or rejected
translation shows English rather than an error. Record content (tickets,
comments, names) is never translated.

Files under serviceops_core/locales/:
  index.json            language metadata: names, script, direction, fallback
  source.json           every extracted message id, flagged when JavaScript uses it
  messages/<code>.json  {"messages": {source: translation}, "calendar": {...}}
"""
import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from string import Formatter
from types import MappingProxyType

from markupsafe import Markup, escape

logger = logging.getLogger(__name__)

LOCALES = Path(__file__).with_name("locales")
SOURCE_LANGUAGE = "en"
AUTOMATIC = "auto"
RTL_SCRIPTS = frozenset({"Adlm", "Arab", "Hebr", "Mand", "Mend", "Nkoo", "Rohg", "Samr", "Syrc", "Thaa", "Yezi"})
_CODE = re.compile(r"[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8}){0,3}")
# Accept-Language and legacy codes that name a bundled language differently.
_ALIASES = MappingProxyType({
    "zh": "zh-Hans", "zh-cn": "zh-Hans", "zh-sg": "zh-Hans", "zh-my": "zh-Hans", "zh-hans-cn": "zh-Hans",
    "zh-tw": "zh-Hant", "zh-hk": "zh-Hant", "zh-mo": "zh-Hant", "zh-hant-tw": "zh-Hant",
    "no": "nb", "nb-no": "nb", "nn-no": "nn", "iw": "he", "in": "id", "ji": "yi", "jw": "jv",
    "tl": "fil", "mo": "ro", "sr-cyrl": "sr", "sr-latn": "sh", "hr-hr": "hr", "pt-pt": "pt",
    "ku-arab": "ckb", "ms-bn": "ms", "fa-af": "prs",
})


def _read_json(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _load_index():
    try:
        raw = _read_json(LOCALES / "index.json")
        languages = raw.get("languages") if isinstance(raw, dict) else None
        if not isinstance(languages, dict) or SOURCE_LANGUAGE not in languages:
            raise ValueError("The language index must describe English")
        index = {}
        for code, entry in languages.items():
            if not isinstance(code, str) or not _CODE.fullmatch(code) or not isinstance(entry, dict):
                raise ValueError(f"Invalid language entry {code!r}")
            name, english_name = entry.get("name"), entry.get("english_name")
            script, fallback = entry.get("script"), entry.get("fallback")
            if not isinstance(name, str) or not name or not isinstance(english_name, str) or not english_name:
                raise ValueError(f"Language {code} needs a name and an English name")
            if not isinstance(script, str) or not re.fullmatch(r"[A-Z][a-z]{3}", script):
                raise ValueError(f"Language {code} needs an ISO 15924 script")
            if fallback is not None and fallback not in languages:
                raise ValueError(f"Language {code} falls back to an unknown language")
            translated = entry.get("translated", 0)
            if not isinstance(translated, int) or translated < 0:
                raise ValueError(f"Language {code} has an invalid translated count")
            index[code] = MappingProxyType({
                "name": name, "english_name": english_name, "script": script,
                "direction": "rtl" if script in RTL_SCRIPTS else "ltr", "fallback": fallback,
                "translated": translated,
            })
        return MappingProxyType(index)
    except (OSError, UnicodeError, ValueError, TypeError, AttributeError):
        logger.exception("The language index could not be loaded; only English is available")
        return MappingProxyType({SOURCE_LANGUAGE: MappingProxyType({
            "name": "English", "english_name": "English", "script": "Latn", "direction": "ltr", "fallback": None,
            "translated": 0})})


def _load_source():
    try:
        raw = _read_json(LOCALES / "source.json")
        rows = raw.get("messages") if isinstance(raw, dict) else None
        if not isinstance(rows, list):
            raise ValueError("source.json must list messages")
        messages, javascript = [], []
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]:
                raise ValueError("Invalid source message")
            messages.append(row["id"])
            if row.get("javascript") is True:
                javascript.append(row["id"])
        return frozenset(messages), tuple(javascript)
    except (OSError, UnicodeError, ValueError, TypeError, AttributeError):
        logger.exception("The source message list could not be loaded")
        return frozenset(), ()


LANGUAGES = _load_index()
SOURCE_MESSAGES, JAVASCRIPT_MESSAGES = _load_source()


class _CatalogStore:
    """Read-only, lazily loaded catalogs; a worker only loads languages in use."""

    def __len__(self):
        return len(LANGUAGES)

    def __iter__(self):
        return iter(LANGUAGES)

    def __contains__(self, code):
        return code in LANGUAGES

    def __getitem__(self, code):
        entry = self.get(code)
        if entry is None:
            raise KeyError(code)
        return entry

    def get(self, code, default=None):
        if code not in LANGUAGES:
            return default
        return _load_catalog(code)

    def values(self):
        return [self[code] for code in LANGUAGES]


@lru_cache(maxsize=64)
def _load_catalog(code):
    empty = MappingProxyType({"messages": MappingProxyType({}), "calendar": MappingProxyType({})})
    if code == SOURCE_LANGUAGE:
        return empty
    path = LOCALES / "messages" / f"{code}.json"
    if not path.is_file():
        return empty
    try:
        raw = _read_json(path)
        messages = raw.get("messages") if isinstance(raw, dict) else None
        if not isinstance(messages, dict):
            raise ValueError("A catalog must contain a messages object")
        accepted = {}
        for source, translated in messages.items():
            if isinstance(source, str) and isinstance(translated, str) and translated.strip():
                accepted[source] = translated
        calendar = raw.get("calendar") if isinstance(raw.get("calendar"), dict) else {}
        checked_calendar = {}
        for key, length in (("months", 12), ("months_abbr", 12), ("days", 7), ("days_abbr", 7)):
            values = calendar.get(key)
            if isinstance(values, list) and len(values) == length and all(isinstance(value, str) and value for value in values):
                checked_calendar[key] = tuple(values)
        return MappingProxyType({"messages": MappingProxyType(accepted), "calendar": MappingProxyType(checked_calendar)})
    except (OSError, UnicodeError, ValueError, TypeError, AttributeError):
        logger.exception("Catalog %s could not be loaded; English is used for it", code)
        return empty


CATALOGS = _CatalogStore()


def canonical_language(code):
    """Map a requested code to a bundled language code, or None."""
    if not isinstance(code, str) or code == AUTOMATIC:
        return None
    code = code.strip().replace("_", "-")
    if not code or len(code) > 35 or not _CODE.fullmatch(code):
        return None
    lowered = code.lower()
    for candidate in (code, _ALIASES.get(lowered)):
        if candidate and candidate in LANGUAGES:
            return candidate
    by_lower = {known.lower(): known for known in LANGUAGES}
    if lowered in by_lower:
        return by_lower[lowered]
    parts = lowered.split("-")
    while len(parts) > 1:
        parts.pop()
        prefix = "-".join(parts)
        if prefix in _ALIASES and _ALIASES[prefix] in LANGUAGES:
            return _ALIASES[prefix]
        if prefix in by_lower:
            return by_lower[prefix]
    return None


def valid_language(code):
    return isinstance(code, str) and code in LANGUAGES


def negotiate(header):
    """Best bundled language for an Accept-Language header, or None."""
    if not isinstance(header, str) or not header.strip():
        return None
    ranked = []
    for position, part in enumerate(header[:512].split(",")):
        tag, _, parameters = part.strip().partition(";")
        quality = 1.0
        for parameter in parameters.split(";"):
            name, _, value = parameter.strip().partition("=")
            if name.strip() == "q":
                try:
                    quality = float(value)
                except ValueError:
                    quality = 0.0
        if tag and tag != "*" and 0 < quality <= 1:
            ranked.append((-quality, position, tag))
    for _, _, tag in sorted(ranked):
        match = canonical_language(tag)
        if match:
            return match
    return None


def _fallback_chain(code):
    seen = []
    while code and code in LANGUAGES and code not in seen and code != SOURCE_LANGUAGE:
        seen.append(code)
        code = LANGUAGES[code]["fallback"]
    return seen


@lru_cache(maxsize=8192)
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


def lookup(message, language):
    """The catalog text for message in language, following fallbacks; else message."""
    for code in _fallback_chain(language):
        entry = CATALOGS.get(code)
        translated = entry["messages"].get(message) if entry else None
        if translated:
            return translated
    return message


def _checked_translation(message, language, parameters):
    translated = lookup(message, language)
    if not parameters:
        return translated
    expected = message_parameters(message)
    if expected != set(parameters):
        raise ValueError("Translation parameter names do not match the source message")
    if translated is not message:
        try:
            matches = message_parameters(translated) == expected
        except ValueError:
            matches = False
        if not matches:
            logger.error("Offline translation parameter mismatch for language %s; using source message", language)
            translated = message
    return translated


def translate(message, language=SOURCE_LANGUAGE, **parameters):
    """Plain-text translation; output is escaped by Jinja like any other string."""
    try:
        translated = _checked_translation(message, language, parameters)
        return translated.format_map(parameters) if parameters else translated
    except (TypeError, ValueError, KeyError):
        logger.exception("Offline message formatting failed for language %s", language)
        raise


def translate_markup(message, language=SOURCE_LANGUAGE, **parameters):
    """HTML-safe translation for templates.

    Catalog text is always escaped, so a translation can never inject markup;
    parameters are escaped unless they are already Markup (icons, badges).
    """
    try:
        translated = _checked_translation(message, language, parameters)
        template = escape(translated)
        if not parameters:
            return template
        return Markup(template).format_map({name: value for name, value in parameters.items()})
    except (TypeError, ValueError, KeyError):
        logger.exception("Offline message formatting failed for language %s", language)
        raise


def translate_plural(count, singular, plural, language=SOURCE_LANGUAGE, **parameters):
    """Select the English singular or plural message, then translate it.

    Languages with more plural categories than English use the translated
    plural message for every count other than one.
    """
    message = singular if count == 1 else plural
    return translate_markup(message, language, count=count, **parameters) if "count" in message_parameters(message) \
        else translate_markup(message, language, **parameters)


def translate_value(value, language=SOURCE_LANGUAGE):
    """Translate a known interface value (a workflow state, priority or role
    label); any other value, including record content, is returned unchanged."""
    if not isinstance(value, str) or value not in SOURCE_MESSAGES:
        return value
    return lookup(value, language)


def tr(message, **parameters):
    """Translate for the current request's language (flash messages, errors)."""
    return translate(message, request_language(), **parameters)


def tr_value(value):
    """translate_value() for the current request's language."""
    return translate_value(value, request_language())


def translatable(message):
    """Mark a module-level display string for extraction; returns it unchanged.

    Display it later through tr() so it is translated for the viewer."""
    return message


@lru_cache(maxsize=64)
def javascript_catalog(language):
    """The translated subset scripts need, embedded as JSON in each page."""
    if language == SOURCE_LANGUAGE or language not in LANGUAGES:
        return MappingProxyType({})
    return MappingProxyType({message: lookup(message, language) for message in JAVASCRIPT_MESSAGES
                             if lookup(message, language) is not message})


def calendar_names(language):
    for code in _fallback_chain(language):
        entry = CATALOGS.get(code)
        if entry and entry["calendar"]:
            return entry["calendar"]
    return MappingProxyType({})


_STRFTIME_TOKEN = re.compile(r"%[-#]?[A-Za-z%]")


def localized_strftime(value, fmt, language=SOURCE_LANGUAGE):
    """strftime with month and weekday names from the bundled CLDR calendar."""
    names = calendar_names(language)
    if not names:
        return value.strftime(fmt)
    replacements = {"%B": ("months", value.month - 1), "%b": ("months_abbr", value.month - 1),
                    "%A": ("days", value.weekday()), "%a": ("days_abbr", value.weekday())}

    def substitute(match):
        token = match.group(0)
        key = replacements.get(token)
        if key and key[0] in names:
            return names[key[0]][key[1]].replace("%", "%%")
        return token

    return value.strftime(_STRFTIME_TOKEN.sub(substitute, fmt))


@lru_cache(maxsize=1)
def language_options():
    """(code, label) pairs for a language picker, sorted by English name.

    Each label shows the language's own name, plus the English name when they
    differ, so a reader of any script can find their language."""
    options = []
    total = len(SOURCE_MESSAGES)
    for code, entry in LANGUAGES.items():
        label = entry["name"] if entry["name"] == entry["english_name"] else f"{entry['name']} — {entry['english_name']}"
        if code != SOURCE_LANGUAGE and total and entry["translated"] < total:
            percent = entry["translated"] * 100 // total
            label += f" · {percent}%" if percent else " · <1%"
        options.append((entry["english_name"].casefold(), code, label))
    return tuple((code, label) for _, code, label in sorted(options))


_default_language = None


def init_app(app, default_language, api_prefix="/api/"):
    """Register template helpers. default_language() returns the instance
    default code; it is read per request so administrators can change it.
    Signed-out requests under api_prefix are machine clients and get English;
    pass None when an app's API serves only its own pages (the installer)."""
    global _default_language
    _default_language = default_language
    app.extensions["serviceops_localization"] = {"default_language": default_language}
    app.config["SERVICEOPS_LANGUAGE_API_PREFIX"] = api_prefix
    app.context_processor(template_context)
    @app.before_request
    def _resolve_interface_language():
        # Resolve once, before any view work, so a later tr() never queries
        # (and autoflushes) in the middle of a business transaction.
        from flask import request
        if request.endpoint != "static":
            request_language()

    app.jinja_env.globals.update(
        tr=lambda message, **parameters: translate_markup(message, request_language(), **parameters),
        trn=lambda count, singular, plural, **parameters: translate_plural(count, singular, plural, request_language(), **parameters),
        tr_value=lambda value: translate_value(value, request_language()),
    )
    # Month and weekday names in the reader's language; no timezone change.
    app.jinja_env.filters["l10n_strftime"] = (
        lambda value, fmt: localized_strftime(value, fmt, request_language()) if value else "")


def instance_default_language():
    provider = _default_language
    try:
        from flask import current_app, has_app_context
        if has_app_context():
            provider = current_app.extensions.get("serviceops_localization", {}).get("default_language", provider)
        configured = canonical_language(provider()) if provider else None
    except Exception:
        logger.exception("The default interface language could not be read; using English")
        configured = None
    return configured or SOURCE_LANGUAGE


def resolve_language(preference, accept_language, api_request):
    """Pure resolution order: explicit preference, then the browser language
    (never for API clients), then the instance default."""
    explicit = canonical_language(preference) if preference and preference != AUTOMATIC else None
    if explicit:
        return explicit
    if api_request and preference is None:
        return SOURCE_LANGUAGE
    return negotiate(accept_language) or instance_default_language()


def request_language():
    """The interface language for the current request (cached on flask.g)."""
    try:
        from flask import current_app, g, has_request_context, request
        if not has_request_context():
            return SOURCE_LANGUAGE
        cached = g.get("serviceops_language")
        if cached:
            return cached
        preference = None
        if getattr(current_app, "login_manager", None) is not None:
            from flask_login import current_user
            if current_user and current_user.is_authenticated:
                from serviceops_models import UserPreference, db
                with db.session.no_autoflush:
                    row = UserPreference.query.filter_by(user_id=current_user.id).first()
                preference = row.language if row else AUTOMATIC
        api_prefix = current_app.config.get("SERVICEOPS_LANGUAGE_API_PREFIX", "/api/")
        language = resolve_language(preference, request.headers.get("Accept-Language", ""),
                                    bool(api_prefix) and request.path.startswith(api_prefix))
        g.serviceops_language = language
        return language
    except Exception:
        logger.exception("The interface language could not be resolved; using English")
        return SOURCE_LANGUAGE


def template_context(language=None):
    language = language if valid_language(language) else request_language()
    entry = LANGUAGES.get(language, LANGUAGES[SOURCE_LANGUAGE])
    return {
        "ui_language": language,
        "ui_direction": entry["direction"],
        "ui_language_name": entry["name"],
        "language_options": language_options(),
        "ui_javascript_catalog": dict(javascript_catalog(language)),
    }
