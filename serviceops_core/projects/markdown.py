"""A small, safe Markdown renderer for work item descriptions and comments
(B-449). Everything is HTML-escaped first; only this fixed subset becomes
markup, so user text can never inject HTML or script:

    # to ###### headings          **bold**  *italic*  ~~strike~~  `code`
    - or * bullet lists           1. numbered lists    > quotes
    ``` fenced code blocks        | tables | with | a | --- | header row |
    [text](https://link) and bare https:// links (http, https, mailto only)
    @username mentions (resolved by the caller), WEB-12 work item keys

Line breaks inside a paragraph are kept.
"""
import re

from markupsafe import Markup, escape

# URLs are matched on escaped text: "&" may only appear as "&amp;", so an
# escaped quote (&#34;) always ends a URL, and so does a code placeholder.
URL_CHARS = r"(?:[^\s<&)\x00\x01]|&amp;)"
LINK = re.compile(r"\[([^\]\n]{1,300})\]\(((?:https?://|mailto:)" + URL_CHARS + r"{1,2000})\)")
BARE_URL = re.compile(r"(?<![\"'=>/\w])(https?://" + URL_CHARS + r"{0,2000}[^\s<&.,;:!?)\]'\"\x00\x01])")
BOLD = re.compile(r"\*\*(?=\S)(.+?)(?<=\S)\*\*")
ITALIC = re.compile(r"(?<![\*\w])\*(?=\S)([^*\n]+?)(?<=\S)\*(?![\*\w])")
STRIKE = re.compile(r"~~(?=\S)(.+?)(?<=\S)~~")
CODE = re.compile(r"`([^`\n]{1,500})`")
HEADING = re.compile(r"^(#{1,6})\s+(.+)$")
BULLET = re.compile(r"^\s*[-*]\s+(.*)$")
NUMBERED = re.compile(r"^\s*\d{1,4}[.)]\s+(.*)$")
TABLE_RULE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")


def _inline(text, mention, item_link):
    """Inline markup on already-escaped text. Code spans are protected first
    so nothing inside them is formatted."""
    codes = []

    def keep_code(match):
        codes.append(match.group(1))
        return f"\x00{len(codes) - 1}\x00"
    text = CODE.sub(keep_code, text)
    links = []

    def keep_link(match):
        links.append(f'<a href="{match.group(2)}" rel="noopener noreferrer" target="_blank">{match.group(1)}</a>')
        return f"\x01{len(links) - 1}\x01"
    text = LINK.sub(keep_link, text)

    def keep_bare(match):
        links.append(f'<a href="{match.group(1)}" rel="noopener noreferrer" target="_blank">{match.group(1)}</a>')
        return f"\x01{len(links) - 1}\x01"
    text = BARE_URL.sub(keep_bare, text)
    text = BOLD.sub(r"<strong>\1</strong>", text)
    text = ITALIC.sub(r"<em>\1</em>", text)
    text = STRIKE.sub(r"<del>\1</del>", text)
    if mention:
        text = mention(text)
    if item_link:
        text = item_link(text)
    text = re.sub("\x01(\\d+)\x01", lambda m: links[int(m.group(1))], text)
    return re.sub("\x00(\\d+)\x00", lambda m: f"<code>{codes[int(m.group(1))]}</code>", text)


def _cells(line):
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [cell.strip() for cell in line.split("|")]


def render(text, mention=None, item_link=None):
    """HTML for `text`. `mention` and `item_link`, when given, receive
    escaped inline text and return it with @mentions or work item keys
    turned into links."""
    # \x00 and \x01 mark protected code spans and links in _inline; they
    # are never meaningful in user text.
    text = (text or "").replace("\x00", "").replace("\x01", "")
    lines = str(escape(text)).replace("\r\n", "\n").split("\n")
    out, paragraph, index = [], [], 0

    def flush():
        if paragraph:
            out.append("<p>" + "<br>".join(_inline(line, mention, item_link) for line in paragraph) + "</p>")
            paragraph.clear()

    while index < len(lines):
        line = lines[index]
        if line.strip().startswith("```"):
            flush()
            block = []
            index += 1
            while index < len(lines) and not lines[index].strip().startswith("```"):
                block.append(lines[index])
                index += 1
            out.append("<pre><code>" + "\n".join(block) + "</code></pre>")
            index += 1
            continue
        heading = HEADING.match(line)
        if heading:
            flush()
            level = len(heading.group(1))
            out.append(f"<h{level + 2 if level < 5 else 6}>{_inline(heading.group(2), mention, item_link)}"
                       f"</h{level + 2 if level < 5 else 6}>")
            index += 1
            continue
        if BULLET.match(line) or NUMBERED.match(line):
            flush()
            ordered = bool(NUMBERED.match(line))
            pattern = NUMBERED if ordered else BULLET
            items = []
            while index < len(lines) and pattern.match(lines[index]):
                items.append("<li>" + _inline(pattern.match(lines[index]).group(1), mention, item_link) + "</li>")
                index += 1
            tag = "ol" if ordered else "ul"
            out.append(f"<{tag}>" + "".join(items) + f"</{tag}>")
            continue
        if line.startswith("&gt;"):
            flush()
            quoted = []
            while index < len(lines) and lines[index].startswith("&gt;"):
                quoted.append(_inline(lines[index][4:].lstrip(), mention, item_link))
                index += 1
            out.append("<blockquote>" + "<br>".join(quoted) + "</blockquote>")
            continue
        if "|" in line and index + 1 < len(lines) and TABLE_RULE.match(lines[index + 1]):
            flush()
            header = _cells(line)
            index += 2
            rows = []
            while index < len(lines) and "|" in lines[index] and lines[index].strip():
                rows.append(_cells(lines[index]))
                index += 1
            head = "".join(f"<th>{_inline(cell, mention, item_link)}</th>" for cell in header)
            body = "".join("<tr>" + "".join(f"<td>{_inline(cell, mention, item_link)}</td>" for cell in row) + "</tr>"
                           for row in rows)
            out.append(f'<div class="md-table"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>')
            continue
        if not line.strip():
            flush()
            index += 1
            continue
        paragraph.append(line)
        index += 1
    flush()
    return Markup("".join(out))
