"""Wrap static interface text in Jinja templates with tr() calls.

A one-way source migration tool, kept for reproducibility and for wrapping new
templates. It rewrites only text the browser would display as prose:

* HTML text nodes, split at tags and at Jinja statements ({% %}). Jinja
  expressions inside a sentence become named parameters, so translators can
  reorder them: ``{{ n }} unread`` -> ``{{ tr('{n} unread', n=(n)) }}``.
* Display attributes (title, placeholder, aria-label, alt, label, ...).
* String literals in output position of an expression
  (``{{ 'A' if x else 'B' }}``, ``{{ x or 'None' }}``, ``x|default('None')``).

Never touched: <script>, <style>, <pre>, <textarea>, <code>, <kbd>, <samp>,
<svg>, <math>, elements marked translate="no", Jinja statements, comparisons,
dictionary keys and call arguments. Anything ambiguous is reported, not
rewritten. Leading/trailing whitespace and symbols stay outside the call, so
English output is unchanged apart from collapsed inner whitespace.
"""
import argparse
import html
import json
import keyword
import re
import sys
import unicodedata
from pathlib import Path

from jinja2 import Environment, TemplateSyntaxError, nodes

SEGMENT = re.compile(r"\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\}", re.S)
PLACEHOLDER = re.compile("(\\d+)")
HUMAN_TEXT = re.compile(r"[A-Za-z]{2,}")
ACRONYM_ONLY = re.compile(r"^[^a-z]*$")
ASCII_SPACE = re.compile(r"[ \t\r\n\f]+")
TAG = re.compile(r"<!--.*?-->|<!(?!--)[^>]*>|<(script|style)\b[^>]*>.*?</\1\s*>|</?[A-Za-z][^>]*>", re.S | re.I)
LEADING_PUNCTUATION = set(",.;:/|›‹»«—–·•")
TRAILING_PUNCTUATION = set("/|›‹»«—–·•")
COLOR_OR_TOKEN = re.compile(r"#?[0-9A-Fa-f]{3,8}|[a-z0-9_.:/-]+|%[A-Za-z%\s:,.-]*")
ATTRIBUTE = re.compile(r"""([^\s"'=<>/]+)(\s*=\s*)("([^"]*)"|'([^']*)')""")
SKIP_ELEMENTS = {"pre", "textarea", "code", "kbd", "samp", "svg", "math", "script", "style"}
VOID_ELEMENTS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
DISPLAY_ATTRIBUTES = {"title", "placeholder", "aria-label", "aria-description", "aria-roledescription",
                      "aria-valuetext", "alt", "label", "data-confirm", "data-empty-text"}
BUTTON_INPUT_TYPES = {"submit", "button", "reset"}
JINJA_KEYWORDS = {"and", "or", "not", "if", "else", "in", "is", "true", "false", "none", "for", "recursive",
                  "with", "without", "context", "import", "from", "as", "block", "loop", "self", "varargs",
                  "kwargs", "caller", "tr"}


def literal(text):
    """A Jinja string literal for text (Jinja decodes backslash escapes)."""
    quote = "'" if "'" not in text else ('"' if '"' not in text else "'")
    escaped = text.replace("\\", "\\\\")
    if quote in escaped:
        escaped = escaped.replace(quote, "\\" + quote)
    return quote + escaped + quote


def is_symbol(character):
    return unicodedata.category(character)[0] == "S" or character in "    ·•"


class Rewriter:
    def __init__(self, source, name):
        self.name = name
        self.source = source
        self.segments = []
        self.reports = []
        self.messages = []

        def stash(match):
            self.segments.append(match.group(0))
            return f"{len(self.segments) - 1}"

        self.flat = SEGMENT.sub(stash, source)

    def segment_kind(self, index):
        return self.segments[index][:2]

    def expression(self, index):
        segment = self.segments[index]
        if segment.startswith("{{-") or segment.endswith("-}}"):
            return None
        return segment[2:-2].strip()

    @staticmethod
    def parameter_name(expression, used):
        base = re.split(r"\||\bif\b|\bor\b|\band\b|\(|\[|~|\+|-|\*|/", expression, maxsplit=1)[0].strip()
        candidate = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", base)
        name = candidate[-1].lower() if candidate else "value"
        if not name.isidentifier() or keyword.iskeyword(name) or name in JINJA_KEYWORDS:
            name = "value"
        unique, counter = name, 2
        while unique in used:
            unique, counter = f"{name}{counter}", counter + 1
        used.add(unique)
        return unique

    def translate_run(self, run, context):
        """Return replacement source for a text run, or None to leave it."""
        indexes = [int(match.group(1)) for match in PLACEHOLDER.finditer(run)]
        if any(self.segment_kind(index) != "{{" for index in indexes):
            raise AssertionError("statement placeholders must be split before translate_run")
        visible = PLACEHOLDER.sub("", run)
        if not HUMAN_TEXT.search(html.unescape(visible)):
            return None
        letters = "".join(re.findall(r"[A-Za-z]+", html.unescape(visible)))
        if ACRONYM_ONLY.match(letters) and len(letters) <= 5:
            return None
        start, end = 0, len(run)
        while start < end and (run[start] in " \t\r\n\f" or is_symbol(run[start]) or run[start] in LEADING_PUNCTUATION):
            start += 1
        while end > start and (run[end - 1] in " \t\r\n\f" or is_symbol(run[end - 1]) or run[end - 1] in TRAILING_PUNCTUATION):
            end -= 1
        core = run[start:end]
        parts, parameters, used = [], [], set()
        position = 0
        for match in PLACEHOLDER.finditer(core):
            text = html.unescape(core[position:match.start()])
            if "{" in text or "}" in text:
                self.reports.append({"template": self.name, "reason": "literal braces", "text": core, "context": context})
                return None
            parts.append(text)
            expression = self.expression(int(match.group(1)))
            if expression is None:
                self.reports.append({"template": self.name, "reason": "whitespace control in sentence", "text": core, "context": context})
                return None
            name = self.parameter_name(expression, used)
            parameters.append((name, expression))
            parts.append("{" + name + "}")
            position = match.end()
        tail = html.unescape(core[position:])
        if "{" in tail or "}" in tail:
            self.reports.append({"template": self.name, "reason": "literal braces", "text": core, "context": context})
            return None
        parts.append(tail)
        message = ASCII_SPACE.sub(" ", "".join(parts)).strip()
        if not message or not HUMAN_TEXT.search(PLACEHOLDER.sub("", message)):
            return None
        self.messages.append({"message": message, "context": context})
        arguments = "".join(f", {name}=({expression})" for name, expression in parameters)
        return run[:start] + "{{ tr(" + literal(message) + arguments + ") }}" + run[end:]

    def translate_text_node(self, text, context):
        pieces = re.split("(\\d+)", text)
        output, run = [], []

        def flush():
            if run:
                joined = "".join(run)
                output.append(self.translate_run(joined, context) or joined)
                run.clear()

        for piece in pieces:
            match = PLACEHOLDER.fullmatch(piece)
            if match and self.segment_kind(int(match.group(1))) != "{{":
                flush()
                output.append(piece)
            else:
                run.append(piece)
        flush()
        return "".join(output)

    def translate_tag(self, tag):
        name_match = re.match(r"<([A-Za-z][A-Za-z0-9-]*)", tag)
        if not name_match:
            return tag
        element = name_match.group(1).lower()
        input_type = re.search(r"""\btype\s*=\s*["']?([A-Za-z]+)""", tag)
        is_button_input = element == "input" and input_type and input_type.group(1).lower() in BUTTON_INPUT_TYPES

        def replace(match):
            attribute = match.group(1).lower()
            if attribute not in DISPLAY_ATTRIBUTES and not (attribute == "value" and is_button_input):
                return match.group(0)
            value = match.group(4) if match.group(4) is not None else match.group(5)
            quote = '"' if match.group(4) is not None else "'"
            if any(self.segment_kind(int(index)) != "{{" for index in PLACEHOLDER.findall(value)):
                if HUMAN_TEXT.search(PLACEHOLDER.sub("", value)):
                    self.reports.append({"template": self.name, "reason": "statement inside attribute", "text": value, "context": f"<{element} {attribute}>"})
                return match.group(0)
            replacement = self.translate_run(value, f"<{element} {attribute}>")
            if replacement is None:
                return match.group(0)
            return f"{match.group(1)}{match.group(2)}{quote}{replacement}{quote}"

        return ATTRIBUTE.sub(replace, tag)

    def rewrite_html(self):
        output, position = [], 0
        skip_stack = []
        for match in TAG.finditer(self.flat):
            text = self.flat[position:match.start()]
            output.append(text if skip_stack else self.translate_text_node(text, self.context_for(output)))
            tag = match.group(0)
            position = match.end()
            if tag.startswith("<!") or match.group(1):
                output.append(tag)
                continue
            closing = tag.startswith("</")
            element = re.match(r"</?([A-Za-z][A-Za-z0-9-]*)", tag).group(1).lower()
            if closing:
                if skip_stack and skip_stack[-1][0] == element:
                    skip_stack[-1][1] -= 1
                    if skip_stack[-1][1] == 0:
                        skip_stack.pop()
                output.append(tag)
                continue
            if skip_stack and skip_stack[-1][0] == element and element not in VOID_ELEMENTS and not tag.endswith("/>"):
                skip_stack[-1][1] += 1
            translate_no = re.search(r"""\btranslate\s*=\s*["']no["']""", tag, re.I)
            output.append(tag if skip_stack else self.translate_tag(tag))
            if (element in SKIP_ELEMENTS or translate_no) and element not in VOID_ELEMENTS and not tag.endswith("/>"):
                if not skip_stack or skip_stack[-1][0] != element:
                    skip_stack.append([element, 1])
        tail = self.flat[position:]
        output.append(tail if skip_stack else self.translate_text_node(tail, "text"))
        self.flat = "".join(output)

    @staticmethod
    def context_for(output):
        for chunk in reversed(output):
            match = re.match(r"<([A-Za-z][A-Za-z0-9-]*)", chunk)
            if match:
                return f"<{match.group(1).lower()}>"
        return "text"

    def rewrite_output_literals(self):
        """Wrap string literals in output position of {{ }} expressions."""
        environment = Environment()
        for index, segment in enumerate(self.segments):
            if not segment.startswith("{{") or segment.startswith("{{-") or segment.endswith("-}}"):
                continue
            body = segment[2:-2]
            try:
                expression = environment.parse("{{" + body + "}}").body[0].nodes[0]
            except (TemplateSyntaxError, IndexError, AttributeError):
                continue
            targets = []

            def visit(node):
                if isinstance(node, nodes.Const) and isinstance(node.value, str):
                    value = node.value
                    letters = "".join(re.findall(r"[A-Za-z]+", value))
                    core = value.strip(" ").strip("".join(ch for ch in value if is_symbol(ch))).strip(" ")
                    display = (" " in core and HUMAN_TEXT.search(core)) or re.fullmatch(r"[A-Z][a-z]+[.!?]?", core)
                    if display and not (ACRONYM_ONLY.match(letters) and len(letters) <= 5) \
                            and "{" not in value and "}" not in value and not COLOR_OR_TOKEN.fullmatch(value):
                        targets.append(value)
                elif isinstance(node, nodes.CondExpr):
                    visit(node.expr1)
                    if node.expr2 is not None:
                        visit(node.expr2)
                elif isinstance(node, nodes.Or):
                    visit(node.left)
                    visit(node.right)
                elif isinstance(node, nodes.And):
                    visit(node.right)
                elif isinstance(node, nodes.Concat):
                    for child in node.nodes:
                        visit(child)
                elif isinstance(node, nodes.Filter) and node.name in {"default", "d"}:
                    visit(node.node)
                    if node.args:
                        visit(node.args[0])

            visit(expression)
            if not targets:
                continue
            rewritten = body
            for value in dict.fromkeys(targets):
                pattern = re.compile(r"(?<![\w.])('" + re.escape(value).replace("'", "\\\\'") + r"'|\"" + re.escape(value) + r"\")")
                start, end = 0, len(value)
                while start < end and (value[start] == " " or is_symbol(value[start])):
                    start += 1
                while end > start and (value[end - 1] == " " or is_symbol(value[end - 1])):
                    end -= 1
                message = ASCII_SPACE.sub(" ", value[start:end]).strip()
                call = "tr(" + literal(message) + ")"
                if value[:start]:
                    call = literal(value[:start]) + " ~ " + call
                if value[end:]:
                    call = call + " ~ " + literal(value[end:])
                if value[:start] or value[end:]:
                    call = "(" + call + ")"
                replaced, count = pattern.subn(lambda match: call, rewritten)
                if count:
                    rewritten = replaced
                    self.messages.append({"message": message, "context": "expression literal"})
                else:
                    self.reports.append({"template": self.name, "reason": "literal not located", "text": value, "context": segment})
            self.segments[index] = "{{" + rewritten + "}}"

    def upgrade_legacy_calls(self):
        for index, segment in enumerate(self.segments):
            if segment.startswith(("{{", "{%")):
                self.segments[index] = re.sub(r"(?<![\w.])t\((?=\s*['\"])", "tr(", segment)

    def result(self):
        self.upgrade_legacy_calls()
        self.rewrite_output_literals()
        self.rewrite_html()
        return PLACEHOLDER.sub(lambda match: self.segments[int(match.group(1))], self.flat)


VALUE_EXPRESSION = re.compile(
    r"(?:[A-Za-z_][A-Za-z0-9_]*\.)*(state|status|stage|priority|impact|urgency|risk|severity|phase|role|"
    r"effective_role|kind|decision|outcome|lifecycle_state|operational_status|relationship_role|"
    r"label|help|hint|help_text)(\|(?:capitalize|title))?"
    # Bare page/section headings handed to templates by Python views.
    r"|(title|description|parent_title|admin_page_title|admin_parent_title|section_title|group_title|summary)")


def wrap_value_displays(source):
    """Route fixed interface values shown as text through tr_value()."""
    rewriter = Rewriter(source, "")
    text_indexes = set()
    position = 0
    for match in TAG.finditer(rewriter.flat):
        text_indexes.update(int(index) for index in PLACEHOLDER.findall(rewriter.flat[position:match.start()]))
        position = match.end()
    text_indexes.update(int(index) for index in PLACEHOLDER.findall(rewriter.flat[position:]))
    changed = 0
    for index in sorted(text_indexes):
        segment = rewriter.segments[index]
        if not segment.startswith("{{") or segment.startswith("{{-") or segment.endswith("-}}"):
            continue
        body = segment[2:-2].strip()
        if VALUE_EXPRESSION.fullmatch(body):
            rewriter.segments[index] = "{{ tr_value(" + body + ") }}"
            changed += 1
        elif body.startswith("tr("):
            def parameter(match):
                expression = match.group(2)
                if VALUE_EXPRESSION.fullmatch(expression.strip()):
                    return f"{match.group(1)}(tr_value({expression.strip()}))"
                return match.group(0)
            updated = re.sub(r"(, [a-z_0-9]+=)\(([^()]*)\)", parameter, body)
            if updated != body:
                rewriter.segments[index] = "{{ " + updated + " }}"
                changed += 1
    return PLACEHOLDER.sub(lambda match: rewriter.segments[int(match.group(1))], rewriter.flat), changed


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--write", action="store_true", help="rewrite templates in place")
    parser.add_argument("--values", action="store_true", help="only wrap fixed interface values with tr_value()")
    parser.add_argument("templates", nargs="*", type=Path)
    args = parser.parse_args()
    paths = [path.resolve() for path in args.templates] or sorted((args.root / "templates").rglob("*.html"))
    environment = Environment()
    summary = {"templates": 0, "changed": 0, "messages": [], "reports": [], "errors": []}
    if args.values:
        total = 0
        for path in paths:
            source = path.read_text(encoding="utf-8")
            rewritten, changed = wrap_value_displays(source)
            environment.parse(rewritten)
            total += changed
            if args.write and rewritten != source:
                path.write_text(rewritten, encoding="utf-8")
        print(json.dumps({"value_displays": total}))
        return 0
    for path in paths:
        source = path.read_text(encoding="utf-8")
        rewriter = Rewriter(source, str(path.relative_to(args.root)))
        rewritten = rewriter.result()
        try:
            environment.parse(rewritten)
        except TemplateSyntaxError as error:
            summary["errors"].append({"template": rewriter.name, "error": str(error), "line": error.lineno})
            continue
        summary["templates"] += 1
        summary["messages"].extend(dict(row, template=rewriter.name) for row in rewriter.messages)
        summary["reports"].extend(rewriter.reports)
        if rewritten != source:
            summary["changed"] += 1
            if args.write:
                path.write_text(rewritten, encoding="utf-8")
    args.report.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"templates": summary["templates"], "changed": summary["changed"],
                      "messages": len(summary["messages"]), "unique": len({row["message"] for row in summary["messages"]}),
                      "reports": len(summary["reports"]), "errors": len(summary["errors"])}))
    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
