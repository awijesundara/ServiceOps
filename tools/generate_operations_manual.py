"""Render the canonical Markdown operations manual as a branded PDF."""
from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "OPERATIONS_MANUAL.md"
OUTPUT = ROOT / "docs" / "ServiceOps_Complete_Platform_Manual.pdf"
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
}


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
    story, paragraph, code = [], [], []
    in_code = False

    def flush_paragraph():
        if paragraph:
            story.append(Paragraph(escape(" ".join(paragraph)), styles["body"]))
            paragraph.clear()

    for raw in SOURCE.read_text().splitlines():
        line = raw.rstrip()
        if line.startswith("```"):
            flush_paragraph()
            if in_code:
                story.append(Paragraph("<br/>".join(escape(row) for row in code), styles["code"]))
                code.clear()
            in_code = not in_code
            continue
        if in_code:
            code.append(line or " ")
            continue
        if not line:
            flush_paragraph()
        elif line.startswith("# "):
            flush_paragraph()
            story.append(Spacer(1, 12 * mm))
            story.append(Paragraph(escape(line[2:]), styles["h1"]))
        elif line.startswith("## "):
            flush_paragraph()
            story.append(Paragraph(escape(line[3:]), styles["h2"]))
        elif line.startswith("### "):
            flush_paragraph()
            story.append(Paragraph(escape(line[4:]), styles["h3"]))
        elif line.startswith("- ["):
            flush_paragraph()
            mark = "□" if "[ ]" in line else "■"
            story.append(Paragraph(f"{mark} {escape(line[6:])}", styles["bullet"]))
        elif line.startswith("- "):
            flush_paragraph()
            story.append(Paragraph(f"• {escape(line[2:])}", styles["bullet"]))
        elif line.startswith(tuple(f"{n}. " for n in range(1, 10))):
            flush_paragraph()
            story.append(Paragraph(escape(line), styles["bullet"]))
        elif line.startswith("|"):
            flush_paragraph()
            if "---" not in line:
                story.append(Paragraph(escape(" · ".join(cell.strip() for cell in line.strip("|").split("|"))),
                                       styles["body"]))
        elif line.startswith("Version "):
            flush_paragraph()
            story.append(Paragraph(escape(line), styles["meta"]))
        else:
            paragraph.append(line)
    flush_paragraph()
    doc = SimpleDocTemplate(str(OUTPUT), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=20 * mm,
                            title="ServiceOps Complete Platform Manual", author="ServiceOps")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    print(OUTPUT)


if __name__ == "__main__":
    build()
