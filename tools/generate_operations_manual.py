"""Render the canonical Markdown operations manual as a branded PDF."""
import re
from html import escape
from pathlib import Path

from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "OPERATIONS_MANUAL.md"
SCREENSHOT_DIR = ROOT / "docs" / "screenshots"
OUTPUT = ROOT / "docs" / "ServiceOps_Complete_Platform_Manual.pdf"
CONTENT_WIDTH = (210 - 36) * mm  # A4 width minus left/right margins
MAX_IMAGE_HEIGHT = 230 * mm  # leaves room for a caption below on one page
TEAL = colors.HexColor("#003E4C")
DARK = colors.HexColor("#002F3A")
AMBER = colors.HexColor("#F9AA3C")
INK = colors.HexColor("#13252B")
MUTED = colors.HexColor("#63767D")
LINE = colors.HexColor("#D8E1E4")

base = getSampleStyleSheet()
styles = {
    "h1": ParagraphStyle("ManualTitle", parent=base["Title"], fontName="Helvetica-Bold",
                         fontSize=29, leading=34, textColor=DARK, spaceAfter=15),
    "h2": ParagraphStyle("ManualChapter", parent=base["Heading1"], fontName="Helvetica-Bold",
                         fontSize=18, leading=23, textColor=TEAL, spaceBefore=15, spaceAfter=8),
    "h3": ParagraphStyle("ManualSection", parent=base["Heading2"], fontName="Helvetica-Bold",
                         fontSize=12, leading=16, textColor=DARK, spaceBefore=10, spaceAfter=5),
    "body": ParagraphStyle("ManualBody", parent=base["BodyText"], fontSize=9.2, leading=13.5,
                           textColor=INK, spaceAfter=6),
    "bullet": ParagraphStyle("ManualBullet", parent=base["BodyText"], fontSize=9.2, leading=13.5,
                             textColor=INK, leftIndent=13, firstLineIndent=-8, spaceAfter=3),
    "code": ParagraphStyle("ManualCode", parent=base["Code"], fontName="Courier", fontSize=7.7,
                           leading=10.5, textColor=DARK, backColor=colors.HexColor("#EEF3F4"),
                           borderColor=LINE, borderWidth=.5, borderPadding=7, spaceAfter=7),
    "meta": ParagraphStyle("ManualMeta", parent=base["BodyText"], fontSize=9, leading=13,
                           textColor=MUTED, spaceAfter=14),
    "caption": ParagraphStyle("ManualCaption", parent=base["BodyText"], fontSize=8.3, leading=11,
                              textColor=MUTED, alignment=1, spaceBefore=4, spaceAfter=12,
                              fontName="Helvetica-Oblique"),
    "toc_h2": ParagraphStyle("ManualTOCChapter", fontName="Helvetica-Bold", fontSize=10.5,
                             leading=15, textColor=TEAL, spaceBefore=6),
    "toc_h3": ParagraphStyle("ManualTOCSection", fontName="Helvetica", fontSize=9.3,
                             leading=13, textColor=INK, leftIndent=11, spaceBefore=1),
    "toc_title": ParagraphStyle("ManualTOCTitle", parent=base["Heading1"], fontName="Helvetica-Bold",
                                fontSize=18, leading=23, textColor=TEAL, spaceBefore=15, spaceAfter=8),
}

# Paragraph style names (not the dict keys above) that mark chapter/section
# headings for the outline pane and the in-document table of contents.
TOC_LEVELS = {"ManualChapter": 0, "ManualSection": 1}

IMAGE_RE = re.compile(r"^!\[(.*?)\]\((.*?)\)$")


def image_flowable(alt_text, rel_path):
    """Builds a scaled Image + caption pair for a screenshot referenced from
    the manual. Screenshots are full-page browser captures at 1440px wide, so
    height varies a lot page to page; both width and a max height are capped
    so a very tall capture (e.g. a long admin list) still fits on one page
    instead of overflowing or being sliced awkwardly across a page break."""
    path = ROOT / "docs" / rel_path
    if not path.exists():
        return None
    with PILImage.open(path) as img:
        px_width, px_height = img.size
    aspect = px_height / px_width
    width = CONTENT_WIDTH
    height = width * aspect
    if height > MAX_IMAGE_HEIGHT:
        height = MAX_IMAGE_HEIGHT
        width = height / aspect
    return KeepTogether([
        Image(str(path), width=width, height=height),
        Paragraph(escape(alt_text), styles["caption"]),
    ])


def table_flowable(rows):
    """Renders a Markdown table as a real reportlab Table with a styled
    header row, instead of collapsing every row (header included) into a
    single flattened line of body text."""
    cell_style = ParagraphStyle("TableCell", parent=styles["body"], fontSize=8.6, leading=11.5, spaceAfter=0)
    header_style = ParagraphStyle("TableHeader", parent=cell_style, textColor=colors.white, fontName="Helvetica-Bold")
    data = []
    for i, row in enumerate(rows):
        style = header_style if i == 0 else cell_style
        data.append([Paragraph(escape(cell), style) for cell in row])
    col_count = max(len(row) for row in rows)
    col_width = CONTENT_WIDTH / col_count
    table = Table(data, colWidths=[col_width] * col_count, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), TEAL),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F7FAFA")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F0F5F5")]),
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


class ManualDocTemplate(SimpleDocTemplate):
    """Adds PDF outline (bookmark pane) entries and drives the in-document
    Table of Contents by watching chapter/section paragraphs as they're laid
    out, since page numbers aren't known until the flowables are placed."""

    def afterFlowable(self, flowable):
        if not isinstance(flowable, Paragraph):
            return
        level = TOC_LEVELS.get(flowable.style.name)
        if level is None:
            return
        text = flowable.getPlainText()
        key = f"toc-{id(flowable)}-{self.page}"
        self.canv.bookmarkPage(key)
        self.canv.addOutlineEntry(text, key, level=level, closed=False)
        self.notify("TOCEntry", (level, text, self.page, key))


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(AMBER)
    canvas.setLineWidth(1.5)
    canvas.line(18 * mm, 14 * mm, 192 * mm, 14 * mm)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(18 * mm, 9 * mm, "ServiceOps Complete Platform Manual")
    canvas.drawRightString(192 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build():
    story, paragraph, code, table_rows = [], [], [], []
    in_code = False
    toc = TableOfContents()
    toc.levelStyles = [styles["toc_h2"], styles["toc_h3"]]
    toc_inserted = False

    def flush_paragraph():
        if paragraph:
            story.append(Paragraph(escape(" ".join(paragraph)), styles["body"]))
            paragraph.clear()

    def flush_table():
        if table_rows:
            story.append(table_flowable(table_rows))
            story.append(Spacer(1, 6 * mm))
            table_rows.clear()

    for raw in SOURCE.read_text().splitlines():
        line = raw.rstrip()
        if line.startswith("```"):
            flush_paragraph()
            flush_table()
            if in_code:
                story.append(Paragraph("<br/>".join(escape(row) for row in code), styles["code"]))
                code.clear()
            in_code = not in_code
            continue
        if in_code:
            code.append(line or " ")
            continue
        image_match = IMAGE_RE.match(line.strip())
        if not line:
            flush_paragraph()
            flush_table()
        elif image_match:
            flush_paragraph()
            flush_table()
            flowable = image_flowable(image_match.group(1), image_match.group(2))
            if flowable:
                story.append(flowable)
            else:
                print(f"WARNING: screenshot not found, skipped in PDF: docs/{image_match.group(2)}")
        elif line.startswith("# "):
            flush_paragraph()
            flush_table()
            story.append(Spacer(1, 12 * mm))
            story.append(Paragraph(escape(line[2:]), styles["h1"]))
        elif line.startswith("## "):
            flush_paragraph()
            flush_table()
            story.append(Paragraph(escape(line[3:]), styles["h2"]))
        elif line.startswith("### "):
            flush_paragraph()
            flush_table()
            story.append(Paragraph(escape(line[4:]), styles["h3"]))
        elif line.startswith("- ["):
            flush_paragraph()
            flush_table()
            mark = "□" if "[ ]" in line else "■"
            story.append(Paragraph(f"{mark} {escape(line[6:])}", styles["bullet"]))
        elif line.startswith("- "):
            flush_paragraph()
            flush_table()
            story.append(Paragraph(f"• {escape(line[2:])}", styles["bullet"]))
        elif line.startswith(tuple(f"{n}. " for n in range(1, 10))):
            flush_paragraph()
            flush_table()
            story.append(Paragraph(escape(line), styles["bullet"]))
        elif line.startswith("|"):
            flush_paragraph()
            if "---" not in line:
                table_rows.append([cell.strip() for cell in line.strip("|").split("|")])
        elif line.startswith("Version "):
            flush_paragraph()
            flush_table()
            story.append(Paragraph(escape(line), styles["meta"]))
            if not toc_inserted:
                story.append(Paragraph("Contents", styles["toc_title"]))
                story.append(toc)
                story.append(PageBreak())
                toc_inserted = True
        else:
            flush_table()
            paragraph.append(line)
    flush_paragraph()
    flush_table()
    doc = ManualDocTemplate(str(OUTPUT), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=20 * mm,
                            title="ServiceOps Complete Platform Manual", author="ServiceOps")
    doc.multiBuild(story, onFirstPage=footer, onLaterPages=footer)
    print(OUTPUT)


if __name__ == "__main__":
    build()
