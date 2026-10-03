"""Render an AI-drafted ticket note with its structure intact.

ServiceOps AI writes notes as plain text in a predictable shape: a "Heading:"
line per section, paragraphs, "1." and "-" lists, `code`, [S1] source
citations and a quoted draft response. Everything is HTML-escaped first and
only that limited structure is added back, so a note can never inject markup.
"""
import re

from markupsafe import Markup, escape

HEADING = re.compile(r"^(?:#{1,4}\s*)?(?P<text>[^.!?:]{2,80}?)\s*:\s*$")
ORDERED = re.compile(r"^\s*(?P<num>\d{1,3})[.)]\s+(?P<text>.+)$")
BULLET = re.compile(r"^\s*[-*•]\s+(?P<text>.+)$")
CODE = re.compile(r"`([^`\n]+)`")
BOLD = re.compile(r"\*\*(?=\S)(.+?)(?<=\S)\*\*")
CITATION = re.compile(r"\[(S\d{1,3})\]")


def _inline(text, mentions_html):
    """Escape one line, keeping @mentions, `code`, **bold** and [S1] citations."""
    pieces = []
    last = 0
    for match in CODE.finditer(text):
        pieces.append(_prose(text[last:match.start()], mentions_html))
        pieces.append(Markup("<code>") + escape(match.group(1)) + Markup("</code>"))
        last = match.end()
    pieces.append(_prose(text[last:], mentions_html))
    return Markup("").join(pieces)


def _prose(text, mentions_html):
    html = str(mentions_html(text))  # already escaped; * [ ] are not touched by escaping
    html = BOLD.sub(r"<strong>\1</strong>", html)
    html = CITATION.sub(r'<span class="ai-note-cite" title="Source \1">\1</span>', html)
    return Markup(html)


def _blocks(body):
    block = []
    for line in body.replace("\r\n", "\n").split("\n"):
        if line.strip():
            block.append(line.rstrip())
        elif block:
            yield block
            block = []
    if block:
        yield block


def render_ai_note(body, mentions_html):
    out = []
    for block in _blocks(body):
        list_kind, items, paragraph = None, [], []

        def flush_paragraph():
            if not paragraph:
                return
            text = " ".join(line.strip() for line in paragraph)
            if len(text) > 2 and text[0] in "\"“" and text[-1] in "\"”":
                out.append(Markup("<blockquote>") + _inline(text[1:-1], mentions_html) + Markup("</blockquote>"))
            else:
                out.append(Markup("<p>") + Markup("<br>").join(_inline(line.strip(), mentions_html) for line in paragraph) + Markup("</p>"))
            paragraph.clear()

        def flush_list():
            nonlocal list_kind
            if not items:
                return
            start = items[0][0]
            open_tag = Markup(f'<ol start="{int(start)}">') if list_kind == "ol" and start != 1 else Markup(f"<{list_kind}>")
            out.append(open_tag + Markup("").join(Markup("<li>") + _inline(text, mentions_html) + Markup("</li>") for _, text in items) + Markup(f"</{list_kind}>"))
            items.clear()
            list_kind = None

        for line in block:
            heading, ordered, bullet = HEADING.match(line), ORDERED.match(line), BULLET.match(line)
            if ordered or bullet:
                kind = "ol" if ordered else "ul"
                flush_paragraph()
                if list_kind and list_kind != kind:
                    flush_list()
                list_kind = kind
                items.append((int(ordered.group("num")) if ordered else 0, (ordered or bullet).group("text")))
            elif heading and not paragraph and not items:
                out.append(Markup('<h4 class="ai-note-heading">') + _inline(heading.group("text"), mentions_html) + Markup("</h4>"))
            elif items and line.startswith((" ", "\t")):
                number, text = items[-1]
                items[-1] = (number, f"{text} {line.strip()}")  # wrapped continuation of a list item
            else:
                flush_list()
                paragraph.append(line)
        flush_paragraph()
        flush_list()
    return Markup("").join(out)
