"""Route user-facing server messages through tr().

A one-way source migration tool. It rewrites the message argument of
flash(...) and the description= of abort(...) when it is a string literal or an
f-string: f-string values become named parameters, so translators can reorder
them. Anything else (concatenation, %-formatting, variables) is reported for
manual review rather than guessed at.
"""
import argparse
import ast
import json
import re
import sys
from pathlib import Path

HUMAN_TEXT = re.compile(r"[A-Za-z]{2,}")
IMPORT_LINE = "from serviceops_core.localization import tr\n"
RESERVED = {"self", "cls", "message", "language", "parameters"}
# Exceptions whose text is shown to the person who triggered them. Worker-only
# sync errors stay English (they are matched and stored by the job runner),
# and AI tool errors go back to the model, not to a person.
USER_FACING_EXCEPTIONS = {"ValueError", "WorkflowConfigurationError", "ClientTriggerConfigurationError",
                          "PriorityConfigurationError", "RTImportError", "ProviderError"}


def message_like(text):
    return bool(HUMAN_TEXT.search(text)) and (" " in text.strip() or text[:1].isupper())


def literal(text):
    return json.dumps(text, ensure_ascii=False)


class Collector(ast.NodeVisitor):
    def __init__(self, source, location):
        self.source = source
        self.location = location
        self.targets = []
        self.reports = []

    def visit_Call(self, node):
        name = node.func.id if isinstance(node.func, ast.Name) else (node.func.attr if isinstance(node.func, ast.Attribute) else "")
        candidates = []
        if name == "flash" and node.args:
            candidates.append(node.args[0])
        if name == "abort":
            candidates.extend(keyword.value for keyword in node.keywords if keyword.arg == "description")
        if name in USER_FACING_EXCEPTIONS and node.args and isinstance(node.args[0], (ast.Constant, ast.JoinedStr)):
            candidates.append(node.args[0])
        for candidate in candidates:
            if isinstance(candidate, ast.Call) and getattr(candidate.func, "id", None) == "tr":
                continue
            if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
                if message_like(candidate.value):
                    self.targets.append(candidate)
            elif isinstance(candidate, ast.JoinedStr):
                self.targets.append(candidate)
            elif not (isinstance(candidate, ast.Name) or isinstance(candidate, ast.Attribute)):
                self.reports.append({"location": f"{self.location}:{candidate.lineno}", "reason": "unsupported message expression",
                                     "source": ast.get_source_segment(self.source, candidate)})
        self.generic_visit(node)


def parameter_name(expression, used):
    node = expression
    base = None
    while isinstance(node, (ast.Call, ast.Subscript)):
        if isinstance(node, ast.Call):
            function = node.func.id if isinstance(node.func, ast.Name) else (node.func.attr if isinstance(node.func, ast.Attribute) else "")
            if function == "len":
                base = "count"
                break
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, (ast.Name, ast.Attribute, ast.Call, ast.Subscript)):
                node = node.func.value
            elif node.args:
                node = node.args[0]
            else:
                node = node.func
        else:
            node = node.value
    if base is None:
        if isinstance(node, ast.Attribute):
            base = node.attr
        elif isinstance(node, ast.Name):
            base = node.id
        else:
            base = "value"
    base = re.sub(r"[^A-Za-z0-9_]", "_", base).strip("_").lower() or "value"
    if not base.isidentifier() or base in RESERVED:
        base = f"{base}_value" if base.isidentifier() else "value"
    name, counter = base, 2
    while name in used:
        name, counter = f"{base}{counter}", counter + 1
    used.add(name)
    return name


def replacement(node, source):
    if isinstance(node, ast.Constant):
        return "tr(" + literal(node.value) + ")", node.value
    parts, arguments, used = [], [], set()
    for value in node.values:
        if isinstance(value, ast.Constant):
            parts.append(str(value.value).replace("{", "{{").replace("}", "}}"))
            continue
        expression = ast.get_source_segment(source, value.value)
        if expression is None or "\n" in expression:
            return None, None
        if value.format_spec is not None:
            specification = value.format_spec
            if not all(isinstance(part, ast.Constant) for part in specification.values):
                return None, None
            spec = "".join(str(part.value) for part in specification.values)
            expression = f"format({expression}, {literal(spec)})"
        if value.conversion == ord("r"):
            expression = f"repr({expression})"
        elif value.conversion == ord("s"):
            expression = f"str({expression})"
        elif value.conversion == ord("a"):
            expression = f"ascii({expression})"
        name = parameter_name(value.value, used)
        parts.append("{" + name + "}")
        arguments.append(f"{name}={expression}")
    message = "".join(parts)
    if not HUMAN_TEXT.search(re.sub(r"\{[a-z_0-9]+\}", "", message)):
        return None, None
    return "tr(" + literal(message) + "".join(", " + argument for argument in arguments) + ")", message


def offsets(source):
    starts, position = [0], 0
    for line in source.splitlines(keepends=True):
        position += len(line)
        starts.append(position)
    return starts


def rewrite(path, root):
    source = path.read_text(encoding="utf-8")
    location = str(path.relative_to(root))
    tree = ast.parse(source, filename=location)
    collector = Collector(source, location)
    collector.visit(tree)
    line_starts = offsets(source)
    encoded = source.encode("utf-8")
    edits, messages = [], []
    for node in collector.targets:
        text, message = replacement(node, source)
        if text is None:
            collector.reports.append({"location": f"{location}:{node.lineno}", "reason": "f-string not convertible",
                                      "source": ast.get_source_segment(source, node)})
            continue
        # ast offsets are UTF-8 byte columns.
        start_line_bytes = source[line_starts[node.lineno - 1]:line_starts[node.lineno]].encode("utf-8")
        end_line_bytes = source[line_starts[node.end_lineno - 1]:line_starts[node.end_lineno]].encode("utf-8")
        start = len(source[:line_starts[node.lineno - 1]].encode("utf-8")) + node.col_offset
        end = len(source[:line_starts[node.end_lineno - 1]].encode("utf-8")) + node.end_col_offset
        assert start_line_bytes and end_line_bytes
        edits.append((start, end, text))
        messages.append({"message": message, "location": f"{location}:{node.lineno}"})
    if not edits:
        return source, messages, collector.reports
    output = encoded
    for start, end, text in sorted(edits, reverse=True):
        output = output[:start] + text.encode("utf-8") + output[end:]
    rewritten = output.decode("utf-8")
    if not re.search(r"^from serviceops_core\.localization import [^\n]*\btr\b", rewritten, re.M) and \
            not re.search(r"^\s*def tr\(", rewritten, re.M):
        module = ast.parse(rewritten)
        insert_after = 0
        for statement in module.body:
            if isinstance(statement, (ast.Import, ast.ImportFrom)) or (
                    isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant) and insert_after == 0):
                insert_after = statement.end_lineno
            elif insert_after:
                break
        lines = rewritten.splitlines(keepends=True)
        lines.insert(insert_after, IMPORT_LINE)
        rewritten = "".join(lines)
    ast.parse(rewritten, filename=location)
    return rewritten, messages, collector.reports


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    paths = [args.root / "app.py", *sorted((args.root / "serviceops_core").rglob("*.py"))]
    summary = {"changed": [], "messages": [], "reports": []}
    for path in paths:
        if path.name == "localization.py":
            continue
        rewritten, messages, reports = rewrite(path, args.root)
        summary["messages"].extend(messages)
        summary["reports"].extend(reports)
        if rewritten != path.read_text(encoding="utf-8"):
            summary["changed"].append(str(path.relative_to(args.root)))
            if args.write:
                path.write_text(rewritten, encoding="utf-8")
    args.report.write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({"files": len(summary["changed"]), "messages": len(summary["messages"]),
                      "unique": len({row["message"] for row in summary["messages"]}), "reports": len(summary["reports"])}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
