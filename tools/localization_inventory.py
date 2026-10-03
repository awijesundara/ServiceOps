"""Inventory untranslated interface text before offline catalog generation.

The report separates HTML labels, explicit messages and review candidates. It
never classifies record values as translations, changes source, or invents text.
"""
import argparse
import ast
from collections import defaultdict
from html.parser import HTMLParser
import json
import logging
from pathlib import Path
import re
import sys

from jinja2 import Environment, TemplateError, nodes

logger = logging.getLogger(__name__)
HUMAN_TEXT = re.compile(r"[A-Za-z]{2,}")
ATTRIBUTES = {"alt", "title", "placeholder", "aria-label", "data-confirm", "data-empty-text"}
DISPLAY_KEYS = {"label", "description", "help", "message", "title", "placeholder", "empty_text"}


def normalize(text):
    return re.sub(r"\s+", " ", text).strip()


class InterfaceHTML(HTMLParser):
    def __init__(self, add):
        super().__init__(convert_charrefs=True)
        self.add = add
        self.excluded = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.excluded.append(tag)
        if not self.excluded:
            for name, value in attrs:
                if name in ATTRIBUTES and value:
                    self.add(value, "html_attribute")

    def handle_endtag(self, tag):
        if self.excluded and self.excluded[-1] == tag:
            self.excluded.pop()

    def handle_data(self, data):
        if not self.excluded:
            self.add(data, "html_text")


def inventory(root):
    entries = defaultdict(lambda: {"locations": set(), "kinds": set()})
    errors = []

    def add(text, kind, path, line=0):
        text = normalize(text)
        if not text or not HUMAN_TEXT.search(text) or text == "__EXPRESSION__":
            return
        location = str(path.relative_to(root)) + (f":{line}" if line else "")
        entries[text]["locations"].add(location)
        entries[text]["kinds"].add(kind)

    environment = Environment()
    for path in sorted((root / "templates").rglob("*.html")):
        try:
            template = environment.parse(path.read_text(encoding="utf-8"))
            fragments = list(template.find_all(nodes.TemplateData))
            parser = InterfaceHTML(lambda text, kind: add(text, kind, path))
            parser.feed(" __EXPRESSION__ ".join(fragment.data for fragment in fragments))
            parser.close()
            for call in template.find_all(nodes.Call):
                if isinstance(call.node, nodes.Name) and call.node.name == "t" and call.args and isinstance(call.args[0], nodes.Const):
                    add(call.args[0].value, "translated_template", path, call.lineno)
            for output in template.find_all(nodes.Output):
                for child in output.nodes:
                    if isinstance(child, nodes.Const) and isinstance(child.value, str):
                        add(child.value, "rendered_template_literal", path, child.lineno)
        except (OSError, UnicodeError, TemplateError, ValueError, TypeError) as error:
            logger.exception("Could not inventory template %s", path)
            errors.append({"path": str(path.relative_to(root)), "error": type(error).__name__})

    python_paths = [root / "app.py", *sorted((root / "serviceops_core").rglob("*.py"))]
    for path in python_paths:
        if path.name == "localization.py":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    function = node.func.id if isinstance(node.func, ast.Name) else (node.func.attr if isinstance(node.func, ast.Attribute) else "")
                    if function in {"flash", "abort"}:
                        candidates = node.args[:1] if function == "flash" else []
                        candidates += [keyword.value for keyword in node.keywords if keyword.arg == "description"]
                        for value in candidates:
                            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                                add(value.value, "server_message", path, value.lineno)
                            elif isinstance(value, ast.JoinedStr):
                                literal = "".join(part.value if isinstance(part, ast.Constant) else "{parameter}" for part in value.values)
                                add(literal, "parameterized_server_message", path, value.lineno)
                elif isinstance(node, ast.Dict):
                    for key, value in zip(node.keys, node.values):
                        if isinstance(key, ast.Constant) and key.value in DISPLAY_KEYS and isinstance(value, ast.Constant) and isinstance(value.value, str):
                            add(value.value, "configuration_label_candidate", path, value.lineno)
        except (OSError, UnicodeError, SyntaxError) as error:
            logger.exception("Could not inventory Python source %s", path)
            errors.append({"path": str(path.relative_to(root)), "error": type(error).__name__})

    # JavaScript literals are review candidates: selectors/API enum values must
    # remain stable even when their display labels are translated.
    quoted = re.compile(r'''(?P<quote>["'`])(?P<text>(?:\\.|(?!["'`]).)*?)(?P=quote)''', re.S)
    for path in sorted((root / "static").rglob("*.js")):
        try:
            source = path.read_text(encoding="utf-8")
            for match in quoted.finditer(source):
                text = match.group("text")
                if " " in text and not text.startswith(("/", "http", "SELECT ", "<")) and "\n" not in text:
                    add(text, "javascript_literal_candidate", path, source.count("\n", 0, match.start()) + 1)
        except (OSError, UnicodeError) as error:
            logger.exception("Could not inventory JavaScript %s", path)
            errors.append({"path": str(path.relative_to(root)), "error": type(error).__name__})

    messages = [{"message": message, "kinds": sorted(entry["kinds"]), "locations": sorted(entry["locations"])} for message, entry in sorted(entries.items())]
    return {"messages": messages, "errors": errors, "summary": {"unique_candidates": len(messages), "by_kind": {kind: sum(kind in entry["kinds"] for entry in messages) for kind in sorted({kind for entry in messages for kind in entry["kinds"]})}}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = inventory(args.root.resolve())
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report["summary"], sort_keys=True))
        return 1 if report["errors"] else 0
    except (OSError, UnicodeError, ValueError):
        logger.exception("Localization inventory failed")
        return 1


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
