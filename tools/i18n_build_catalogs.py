"""Build the bundled interface catalogs under serviceops_core/locales/.

  extract   collect every message id from templates (tr/trn), Python
            (tr/translatable/translate_plural) and scripts (tr) into source.json
  index     write index.json for a list of languages, with names, script and
            fallback taken from Unicode CLDR (requires Babel, a dev dependency)
  catalogs  assemble messages/<code>.json from translation files, keeping only
            entries that pass the quality checks, and add CLDR calendar names

Translation inputs are JSON files of {"<code>": {"<source>": "<translation>"}};
later inputs override earlier ones, so reviewed or assistant-authored terms can
be layered over machine translation. Nothing here calls a network service.
"""
import argparse
import ast
import json
import re
import sys
import unicodedata
from pathlib import Path
from string import Formatter

from jinja2 import Environment, TemplateSyntaxError, nodes

ROOT = Path(__file__).resolve().parents[1]
LOCALES = ROOT / "serviceops_core" / "locales"
JS_CALL = re.compile(r"""(?<![\w$.])(?:tr|trNoop)\(\s*(?:"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)')""")
PYTHON_SINGLE = {"tr", "translatable"}
PYTHON_PLURAL = {"translate_plural", "trn"}
LETTER_SCRIPT = re.compile(r"[^\W\d_]")


def parameter_names(message):
    names = set()
    for _, name, specification, conversion in Formatter().parse(message):
        if name is None:
            continue
        if not name.isidentifier() or specification or conversion:
            raise ValueError(f"Only simple named parameters are supported: {message!r}")
        names.add(name)
    return frozenset(names)


def _javascript_string(raw):
    """Decode the body of a JavaScript string literal via JSON escapes."""
    converted = re.sub(r"\\x([0-9A-Fa-f]{2})", lambda match: "\\u00" + match.group(1), raw.replace("\\'", "'"))
    converted = re.sub(r'(?<!\\)"', '\\"', converted)
    try:
        return json.loads('"' + converted + '"')
    except json.JSONDecodeError as error:
        raise ValueError(f"Unsupported escape in script message {raw!r}") from error


def extract(root=ROOT):
    """Every message id in the source, flagged when a script needs it."""
    found = {}
    errors = []

    def add(message, location, javascript=False):
        if not isinstance(message, str) or not message.strip():
            errors.append(f"{location}: empty message")
            return
        try:
            parameter_names(message)
        except ValueError as error:
            errors.append(f"{location}: {error}")
            return
        entry = found.setdefault(message, {"javascript": False, "locations": set()})
        entry["javascript"] = entry["javascript"] or javascript
        entry["locations"].add(location)

    environment = Environment()
    template_paths = [*sorted((root / "templates").rglob("*.html")), *sorted((root / "installer" / "templates").rglob("*.html"))]
    for path in template_paths:
        location = str(path.relative_to(root))
        try:
            source = path.read_text(encoding="utf-8")
            template = environment.parse(source)
        except (OSError, UnicodeError, TemplateSyntaxError) as error:
            errors.append(f"{location}: {error}")
            continue
        # Inline page scripts call the same tr(); their messages ship to the browser.
        for script in re.finditer(r"<script(?![^>]*application/json)[^>]*>(.*?)</script\b[^>]*>", source, re.S | re.I):
            for match in JS_CALL.finditer(script.group(1)):
                raw = match.group(1) if match.group(1) is not None else match.group(2)
                try:
                    add(_javascript_string(raw), f"{location}:script", javascript=True)
                except ValueError as error:
                    errors.append(f"{location}: {error}")
        for call in template.find_all(nodes.Call):
            if not isinstance(call.node, nodes.Name):
                continue
            positions = {"tr": (0,), "trn": (1, 2)}.get(call.node.name, ())
            for position in positions:
                if len(call.args) > position:
                    argument = call.args[position]
                    if isinstance(argument, nodes.Const) and isinstance(argument.value, str):
                        add(argument.value, location)
                    elif call.node.name == "trn":
                        errors.append(f"{location}:{call.lineno}: trn() needs literal text")

    python_paths = [root / "app.py", root / "installer" / "app.py", *sorted((root / "serviceops_core").rglob("*.py"))]
    for path in python_paths:
        location = str(path.relative_to(root))
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=location)
        except (OSError, UnicodeError, SyntaxError) as error:
            errors.append(f"{location}: {error}")
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.id if isinstance(node.func, ast.Name) else (node.func.attr if isinstance(node.func, ast.Attribute) else "")
            positions = (0,) if name in PYTHON_SINGLE else ((1, 2) if name in PYTHON_PLURAL else ())
            for position in positions:
                if len(node.args) > position:
                    argument = node.args[position]
                    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                        add(argument.value, f"{location}:{node.lineno}")
                    elif name == "translatable":
                        errors.append(f"{location}:{node.lineno}: translatable() needs literal text")

    for path in sorted((root / "static").rglob("*.js")):
        location = str(path.relative_to(root))
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            errors.append(f"{location}: {error}")
            continue
        for match in JS_CALL.finditer(source):
            raw = match.group(1) if match.group(1) is not None else match.group(2)
            try:
                add(_javascript_string(raw), f"{location}:{source.count(chr(10), 0, match.start()) + 1}", javascript=True)
            except ValueError as error:
                errors.append(f"{location}: {error}")
    return found, errors


def write_source(found, path):
    rows = [{"id": message, "javascript": True} if entry["javascript"] else {"id": message}
            for message, entry in sorted(found.items())]
    path.write_text(json.dumps({"schema": 1, "messages": rows}, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


# --- CLDR metadata -----------------------------------------------------------

def _babel():
    try:
        import babel
        from babel import Locale, UnknownLocaleError
        from babel.core import get_global
        return babel, Locale, UnknownLocaleError, get_global
    except ImportError as error:
        raise SystemExit("Babel is required for CLDR metadata: pip install -r requirements-dev.txt") from error


def _script_of(code, likely):
    """The script a CLDR locale id writes in, explicit or from likely subtags."""
    parts = code.split("_")
    explicit = next((part for part in parts[1:] if re.fullmatch(r"[A-Z][a-z]{3}", part)), None)
    if explicit:
        return explicit
    region = next((part for part in parts[1:] if re.fullmatch(r"[A-Z]{2}|\d{3}", part)), None)
    guess = (likely.get(f"{parts[0]}_{region}") if region else None) or likely.get(parts[0])
    return next((part for part in guess.split("_")[1:] if re.fullmatch(r"[A-Z][a-z]{3}", part)), None) if guess else None


def cldr_metadata(code, extra_names=None, script_override=None):
    """Names, script and fallback for a BCP 47 code, from CLDR (Babel).

    The language's own name is used only when CLDR has it in the same script
    as this variant; otherwise the English name stands in for it."""
    _, Locale, UnknownLocaleError, get_global = _babel()
    parts = code.split("-")
    language = parts[0]
    region = next((part for part in parts[1:] if re.fullmatch(r"[A-Z]{2}|\d{3}", part)), None)
    likely = get_global("likely_subtags")
    script = script_override or _script_of(code.replace("-", "_"), likely)
    if not script:
        raise ValueError(f"No script is known for {code}")
    explicit_script = any(part == script for part in parts[1:])
    english = Locale("en")
    candidates = [f"{language}_{script}_{region}" if region else None, f"{language}_{script}",
                  f"{language}_{region}" if region else None, language]
    autonym = english_name = None
    for candidate in filter(None, candidates):
        try:
            locale = Locale.parse(candidate)
        except (UnknownLocaleError, ValueError):
            continue
        if _script_of(str(locale), likely) != script:
            continue
        try:
            shown = Locale(locale.language, territory=region, script=script if explicit_script else None)
            autonym = shown.get_display_name(shown)
            english_name = shown.get_display_name(english)
        except (UnknownLocaleError, ValueError):
            autonym = locale.get_display_name(locale)
            english_name = locale.get_display_name(english)
        break
    if not english_name:
        base = english.languages.get(language) or (extra_names or {}).get(code) or (extra_names or {}).get(language)
        if base:
            qualifiers = [english.scripts.get(script) if explicit_script else None, english.territories.get(region) if region else None]
            qualifiers = [item for item in qualifiers if item and item not in base]
            english_name = base + (f" ({', '.join(qualifiers)})" if qualifiers else "")
    if extra_names and extra_names.get(code):
        english_name = extra_names[code]
    if not english_name:
        raise ValueError(f"No English name is known for {code}")
    name = autonym or english_name
    name = name[:1].upper() + name[1:]
    english_name = english_name[:1].upper() + english_name[1:]
    fallback = None
    if region or explicit_script:
        if _script_of(language, likely) == script:
            fallback = language
    return {"name": name, "english_name": english_name, "script": script, "fallback": fallback}


def calendar(code):
    _, Locale, UnknownLocaleError, _ = _babel()
    babel_code = code.replace("-", "_")
    try:
        locale = Locale.parse(babel_code)
    except (UnknownLocaleError, ValueError):
        return None
    try:
        months = locale.months["format"]
        days = locale.days["format"]
        result = {
            "months": [str(months["wide"][index]) for index in range(1, 13)],
            "months_abbr": [str(months["abbreviated"][index]) for index in range(1, 13)],
            "days": [str(days["wide"][index]) for index in range(7)],
            "days_abbr": [str(days["abbreviated"][index]) for index in range(7)],
        }
    except (KeyError, TypeError):
        return None
    return result


# --- Quality checks ----------------------------------------------------------

def dominant_script(text):
    counts = {}
    for character in text:
        if LETTER_SCRIPT.match(character):
            try:
                name = unicodedata.name(character)
            except ValueError:
                continue
            script = name.split(" ")[0]
            counts[script] = counts.get(script, 0) + 1
    return max(counts, key=counts.get) if counts else None


SCRIPT_WORDS = {
    "Latn": {"LATIN"}, "Cyrl": {"CYRILLIC"}, "Arab": {"ARABIC"}, "Hebr": {"HEBREW"}, "Grek": {"GREEK"},
    "Deva": {"DEVANAGARI"}, "Beng": {"BENGALI"}, "Guru": {"GURMUKHI"}, "Gujr": {"GUJARATI"}, "Orya": {"ORIYA"},
    "Taml": {"TAMIL"}, "Telu": {"TELUGU"}, "Knda": {"KANNADA"}, "Mlym": {"MALAYALAM"}, "Sinh": {"SINHALA"},
    "Thai": {"THAI"}, "Laoo": {"LAO"}, "Mymr": {"MYANMAR"}, "Khmr": {"KHMER"}, "Tibt": {"TIBETAN"},
    "Geor": {"GEORGIAN"}, "Armn": {"ARMENIAN"}, "Ethi": {"ETHIOPIC"}, "Hang": {"HANGUL"}, "Kore": {"HANGUL", "CJK"},
    "Hans": {"CJK"}, "Hant": {"CJK"}, "Jpan": {"CJK", "HIRAGANA", "KATAKANA"}, "Thaa": {"THAANA"},
    "Syrc": {"SYRIAC"}, "Tfng": {"TIFINAGH"}, "Cans": {"CANADIAN"}, "Cher": {"CHEROKEE"}, "Mtei": {"MEETEI"},
    "Olck": {"OL"}, "Nkoo": {"NKO"}, "Adlm": {"ADLAM"}, "Vaii": {"VAI"}, "Yiii": {"YI"},
}


def check_translation(source, translated, script):
    """Return None when acceptable, else the rejection reason."""
    if not isinstance(translated, str) or not translated.strip():
        return "empty"
    if "\n" in translated and "\n" not in source:
        return "line break added"
    try:
        if parameter_names(translated) != parameter_names(source):
            return "parameters changed"
    except ValueError:
        return "invalid parameter syntax"
    if re.search(r"[<>]", translated) and not re.search(r"[<>]", source):
        return "markup added"
    visible_source = re.sub(r"\{[A-Za-z_][A-Za-z0-9_]*\}", "", source)
    visible = re.sub(r"\{[A-Za-z_][A-Za-z0-9_]*\}", "", translated)
    if len(visible) > max(24, 3 * len(visible_source)):
        return "too long"
    source_words = re.findall(r"[A-Za-z]{3,}", visible_source)
    if script not in {"Latn", None} and len(source_words) <= 3 and any(word in visible for word in source_words):
        return "English source echoed"
    words = re.findall(r"\w+", visible.casefold())
    if len(words) >= 8 and len(set(words)) <= len(words) // 4:
        return "repetition"
    expected = SCRIPT_WORDS.get(script)
    actual = dominant_script(visible)
    if expected and actual and actual not in expected and len(re.findall(r"[^\W\d_]", visible)) >= 3:
        return f"script {actual} instead of {script}"
    return None


def build_catalogs(index, inputs, source_messages):
    report = {}
    for code, meta in index["languages"].items():
        if code == "en":
            continue
        merged = {}
        for layer in inputs:
            merged.update({key: value for key, value in layer.get(code, {}).items() if key in source_messages})
        accepted, rejected = {}, {}
        for message, translated in sorted(merged.items()):
            reason = check_translation(message, translated, meta["script"])
            if reason:
                rejected[message] = reason
            else:
                accepted[message] = translated
        document = {"language": code, "messages": accepted}
        names = calendar(code)
        if names:
            document["calendar"] = names
        (LOCALES / "messages").mkdir(parents=True, exist_ok=True)
        (LOCALES / "messages" / f"{code}.json").write_text(
            json.dumps(document, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        report[code] = {"translated": len(accepted), "rejected": len(rejected),
                        "rejections": dict(sorted(rejected.items())[:50])}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    extract_command = commands.add_parser("extract")
    extract_command.add_argument("--check", action="store_true", help="fail if source.json is out of date")
    index_command = commands.add_parser("index")
    index_command.add_argument("--languages", type=Path, required=True,
                               help='JSON list of codes, or {"<code>": {"english_name": ...}} for names CLDR lacks')
    catalogs_command = commands.add_parser("catalogs")
    catalogs_command.add_argument("--input", type=Path, action="append", default=[])
    catalogs_command.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    if args.command == "extract":
        found, errors = extract()
        if errors:
            print("\n".join(errors), file=sys.stderr)
            return 1
        if args.check:
            current = json.loads((LOCALES / "source.json").read_text(encoding="utf-8"))
            expected = [{"id": message, "javascript": True} if entry["javascript"] else {"id": message}
                        for message, entry in sorted(found.items())]
            if current.get("messages") != expected:
                print("serviceops_core/locales/source.json is out of date: run tools/i18n_build_catalogs.py extract", file=sys.stderr)
                return 1
            return 0
        write_source(found, LOCALES / "source.json")
        print(json.dumps({"messages": len(found), "javascript": sum(entry["javascript"] for entry in found.values())}))
        return 0

    if args.command == "index":
        requested = json.loads(args.languages.read_text(encoding="utf-8"))
        extra = requested if isinstance(requested, dict) else {}
        codes = list(requested)
        languages = {"en": {"name": "English", "english_name": "English", "script": "Latn"}}
        for code in codes:
            if code == "en":
                continue
            meta = cldr_metadata(code, {key: value.get("english_name") for key, value in extra.items() if isinstance(value, dict)},
                                 script_override=(extra.get(code) or {}).get("script") if isinstance(extra.get(code), dict) else None)
            entry = {key: value for key, value in meta.items() if value is not None}
            if isinstance(extra.get(code), dict):
                entry.update({key: value for key, value in extra[code].items() if key in {"name", "english_name", "script", "fallback"}})
            languages[code] = entry
        for entry in languages.values():
            if entry.get("fallback") not in languages:
                entry.pop("fallback", None)
        (LOCALES / "index.json").write_text(json.dumps({"schema": 1, "source_language": "en", "languages": languages},
                                                       ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(json.dumps({"languages": len(languages)}))
        return 0

    index = json.loads((LOCALES / "index.json").read_text(encoding="utf-8"))
    source = json.loads((LOCALES / "source.json").read_text(encoding="utf-8"))
    source_messages = {row["id"] for row in source["messages"]}
    inputs = [json.loads(path.read_text(encoding="utf-8")) for path in args.input]
    report = build_catalogs(index, inputs, source_messages)
    # Effective coverage follows each language's fallback chain (pt-BR -> pt).
    accepted = {code: set(json.loads((LOCALES / "messages" / f"{code}.json").read_text(encoding="utf-8"))["messages"])
                for code in report}
    for code, entry in index["languages"].items():
        if code == "en":
            continue
        covered, chain = set(), code
        while chain and chain != "en" and chain in accepted:
            covered |= accepted[chain]
            chain = index["languages"][chain].get("fallback")
        entry["translated"] = len(covered & source_messages)
    index["message_count"] = len(source_messages)
    (LOCALES / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({code: row["translated"] for code, row in report.items()}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
