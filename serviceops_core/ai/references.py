"""Convert verified evidence markers to readable, application-owned links."""
import re
from urllib.parse import unquote, urlsplit

from flask import url_for

MARKER = re.compile(r"\[S\d{1,3}\]|\bS\d{1,3}\b")
LINK = re.compile(r"\[([^\]\n]{1,200})\]\(([^\s()]{1,1000})\)")
ENDPOINTS = {
    "ticket": ("ticket_detail", "ticket_id"),
    "knowledge": ("knowledge_detail", "article_id"),
    "ci": ("ci_edit", "ci_id"),
    "enterprise": ("enterprise_detail", "record_id"),
    "request": ("request_detail", "request_id"),
    "work_task": ("operational_task_detail", "task_id"),
    "client_ticket": ("client_ticket_detail", "ticket_id"),
}


def safe_reference_url(value):
    """Accept local application paths only; never model-supplied remote URLs."""
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//"):
        return False
    decoded = unquote(value)
    if decoded.startswith("//") or any(ord(char) < 32 or char in "\\<>\"" for char in decoded):
        return False
    parsed = urlsplit(value)
    return not parsed.scheme and not parsed.netloc


def source_links(sources):
    for source in sources:
        if source.get("kind") == "ticket" and not source.get("number"):
            # Older investigation records used the verified number as the title prefix.
            source["number"] = source.get("title", "").split(" ", 1)[0]
        endpoint = ENDPOINTS.get(source.get("kind"))
        if endpoint:
            source["url"] = url_for(endpoint[0], **{endpoint[1]: source["record_id"]})
        elif source.get("kind") == "asset":
            source["url"] = url_for("assets", q=source.get("number", ""))
        else:
            source.pop("url", None)
    return sources


def readable_references(text, sources):
    """Use source metadata, preserving claims while removing opaque labels."""
    by_id = {source.get("id"): source for source in sources}

    def replace(match):
        source = by_id.get(match.group(0).strip("[]"))
        if not source:
            return ""
        label = str(source.get("number") or source.get("title") or "Reference")
        label = re.sub(r"[\[\]\r\n]", " ", label).strip()[:200]
        url = source.get("url")
        return f"[{label}]({url})" if safe_reference_url(url) else label

    numbered = {str(source["number"]): source for source in sources if source.get("number")}
    tokens = re.compile(MARKER.pattern + ("|(?<![\\w-])(?:" + "|".join(re.escape(number) for number in sorted(numbered, key=len, reverse=True)) + ")(?![\\w-])" if numbered else ""))

    def resolve(match):
        source = numbered.get(match.group(0))
        if source:
            label, url = match.group(0), source.get("url")
            return f"[{label}]({url})" if safe_reference_url(url) else label
        return replace(match)

    # Existing valid Markdown links are retained so conversion is idempotent.
    pieces, position = [], 0
    for match in LINK.finditer(text):
        pieces.append(tokens.sub(resolve, text[position:match.start()]))
        pieces.append(match.group(0))
        position = match.end()
    pieces.append(tokens.sub(resolve, text[position:]))
    return _collapse_repeated_links("".join(pieces))


def _collapse_repeated_links(text):
    """Drop a Markdown link that only repeats the link just before it, with
    nothing but whitespace between (a model citing the same source twice).
    One pass over LINK matches -- a backreference regex was quadratic."""
    kept, position, previous = [], 0, None
    for match in LINK.finditer(text):
        gap = text[position:match.start()]
        if previous == match.group(0) and gap and not gap.strip():
            position = match.end()
            continue
        kept.append(gap)
        kept.append(match.group(0))
        previous, position = match.group(0), match.end()
    kept.append(text[position:])
    return "".join(kept)
