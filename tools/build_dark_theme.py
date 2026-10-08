"""Generate static/dark.css: the per-user dark theme.

Every color-bearing declaration in the light stylesheets is re-emitted under
``html.theme-dark`` with its literal colors remapped for a dark surface, in
the same order base.html loads the stylesheets. Copying all color
declarations (including ones that only reference var(--token)) keeps the
light theme's cascade intact: the prefix raises every copy's specificity by
the same amount, so the rule that wins in light mode still wins in dark mode.

Remapping works in OKLCH and depends on what the color paints: light
surfaces become dark surfaces (pure white cards sit slightly above the page
background, as in the light theme), dark text becomes light text, and light
hairlines become dark hairlines. Saturated mid-tone fills such as buttons
keep their color. Theme tokens (custom properties) and anything the mapping
gets wrong are tuned by hand in DARK_TOKENS below.

Run after changing any stylesheet; tests fail while static/dark.css is stale:

    python3 tools/build_dark_theme.py          # rewrite static/dark.css
    python3 tools/build_dark_theme.py --check  # exit 1 when out of date
"""
import argparse
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "static"
TARGET = STATIC / "dark.css"
SCOPE = "html.theme-dark"

# base.html load order. Stylesheets loaded only on some pages are still
# listed in their position so cross-file overrides resolve as they do there.
SOURCES = [
    "app.css", "enterprise.css", "itil.css", "platform.css", "rtl.css",
    "task-board.css", "status-page.css", "brand.css", "admin-workspace.css",
    "notification-audiences.css", "utilities.css", "client-management.css", "integrations.css",
    "ai-chat.css",
]

BACKGROUND = {"background", "background-color", "background-image"}
TEXT = {"color", "caret-color", "text-decoration-color", "-webkit-text-fill-color"}
# SVG fill paints both text and shapes: light fills are surfaces, dark fills ink.
FILL = {"fill"}
LINE = {
    "border", "border-color", "border-top", "border-right", "border-bottom", "border-left",
    "border-top-color", "border-right-color", "border-bottom-color", "border-left-color",
    "border-block", "border-block-start", "border-block-end", "border-inline",
    "border-inline-start", "border-inline-end", "border-inline-start-color",
    "border-inline-end-color", "outline", "outline-color", "column-rule", "stroke",
    "accent-color", "scrollbar-color",
}
SHADOW = {"box-shadow", "text-shadow"}
PROPERTIES = BACKGROUND | TEXT | FILL | LINE | SHADOW

HEX = re.compile(r"#([0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{4}|[0-9a-fA-F]{3})\b")
RGB = re.compile(r"rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)(?:\s*[,/]\s*([\d.]+%?))?\s*\)")
NAMED = re.compile(r"(?<![-\w#])(white|black)(?![-\w])")
COLOR = re.compile(HEX.pattern + "|" + RGB.pattern + "|" + NAMED.pattern)
# Theme tokens are hand-tuned; the light rules that set them are not copied.
CUSTOM_PROPERTY = re.compile(r"^--")


# --- color math (OKLab / OKLCH, sRGB D65) ---------------------------------

def _to_linear(channel):
    return channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4


def _from_linear(channel):
    return 12.92 * channel if channel <= 0.0031308 else 1.055 * channel ** (1 / 2.4) - 0.055


def rgb_to_oklch(red, green, blue):
    r, g, b = (_to_linear(value / 255) for value in (red, green, blue))
    l_ = (0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b) ** (1 / 3)
    m_ = (0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b) ** (1 / 3)
    s_ = (0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b) ** (1 / 3)
    lightness = 0.2104542553 * l_ + 0.7936177850 * m_ - 0.0040720468 * s_
    a = 1.9779984951 * l_ - 2.4285922050 * m_ + 0.4505937099 * s_
    b2 = 0.0259040371 * l_ + 0.7827717662 * m_ - 0.8086757660 * s_
    return lightness, math.hypot(a, b2), math.atan2(b2, a)


def _oklch_to_linear(lightness, chroma, hue):
    a, b = chroma * math.cos(hue), chroma * math.sin(hue)
    l_ = (lightness + 0.3963377774 * a + 0.2158037573 * b) ** 3
    m_ = (lightness - 0.1055613458 * a - 0.0638541728 * b) ** 3
    s_ = (lightness - 0.0894841775 * a - 1.2914855480 * b) ** 3
    return (
        4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_,
        -1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_,
        -0.0041960863 * l_ - 0.7034186147 * m_ + 1.7076147010 * s_,
    )


def oklch_to_rgb(lightness, chroma, hue):
    """Converts back to sRGB, reducing chroma until the color is in gamut."""
    lightness = min(1.0, max(0.0, lightness))
    for _ in range(40):
        linear = _oklch_to_linear(lightness, chroma, hue)
        if all(-1e-4 <= value <= 1 + 1e-4 for value in linear):
            break
        chroma *= 0.9
    return tuple(round(min(1.0, max(0.0, _from_linear(min(1.0, max(0.0, v))))) * 255) for v in linear)


# --- role-aware remapping -------------------------------------------------

# Neutral light surfaces pick up the slight cool tint of the dark tokens.
_SURFACE_HUE = None


def _surface_tint(chroma, hue):
    global _SURFACE_HUE
    if _SURFACE_HUE is None:
        _SURFACE_HUE = rgb_to_oklch(0x18, 0x21, 0x28)[2]
    return (0.012, _SURFACE_HUE) if chroma < 0.012 else (chroma, hue)


def remap(rgb, alpha, role):
    lightness, chroma, hue = rgb_to_oklch(*rgb)
    if role == "fill":
        if lightness >= 0.76 and chroma > 0.08:
            return rgb, alpha  # vivid marks (status dots, highlights) keep their color
        role = "background" if lightness >= 0.76 else "text"
    if role == "background":
        if alpha < 0.5 and lightness < 0.5:
            # A faint dark wash (hover/selection tint) becomes a faint light wash.
            return (255, 255, 255), alpha
        if alpha < 0.5 and lightness >= 0.8:
            return rgb, alpha  # light overlays on brand chrome work on any surface
        if lightness >= 0.995:
            return (0x18, 0x21, 0x28), alpha  # cards and panels: --white, raised above the page
        elif lightness >= 0.76:
            # Tints inside cards sit just below the card, never below the page.
            lightness = max(0.205, 1.185 - lightness)
            chroma, hue = _surface_tint(min(chroma, 0.045 + 0.35 * (1 - lightness) * chroma), hue)
        elif lightness < 0.3 and chroma < 0.04:
            lightness = max(lightness, 0.17)  # near-black chrome stays near-black
        else:
            return rgb, alpha  # saturated fills (buttons, badges) keep their color
    elif role == "text":
        if lightness < 0.64:
            lightness = 0.985 - 0.52 * lightness
            chroma = min(chroma, 0.13)
        elif lightness < 0.8 and chroma > 0.06:
            lightness = max(lightness, 0.74)
        else:
            return rgb, alpha  # already light: white text on fills stays white
    elif role == "line":
        if alpha < 0.5 and lightness >= 0.8:
            return rgb, alpha
        if lightness >= 0.7:
            lightness = max(0.3, 1.24 - lightness)
            chroma, hue = _surface_tint(min(chroma, 0.04), hue)
        elif lightness < 0.5 and chroma > 0.04:
            lightness = 0.985 - 0.52 * lightness  # dark accent rules and stripes stay visible
            chroma = min(chroma, 0.13)
        else:
            return rgb, alpha
    elif role == "shadow":
        if lightness >= 0.8:
            lightness = 1.0 - lightness  # light glows become dark ones
        else:
            return (0, 0, 0), min(1.0, alpha * 2.2 + 0.08)
    return oklch_to_rgb(lightness, chroma, hue), alpha


def _format(rgb, alpha):
    if alpha >= 0.999:
        return "#%02x%02x%02x" % rgb
    return "rgba(%d,%d,%d,%s)" % (*rgb, ("%.3f" % alpha).rstrip("0").rstrip("."))


def _parse(match):
    text = match.group(0)
    if text.lower() == "white":
        return (255, 255, 255), 1.0
    if text.lower() == "black":
        return (0, 0, 0), 1.0
    if text.startswith("#"):
        digits = text[1:]
        if len(digits) in (3, 4):
            digits = "".join(ch * 2 for ch in digits)
        channels = tuple(int(digits[i:i + 2], 16) for i in (0, 2, 4))
        alpha = int(digits[6:8], 16) / 255 if len(digits) == 8 else 1.0
        return channels, alpha
    parts = RGB.match(text).groups()
    channels = tuple(round(float(value)) for value in parts[:3])
    alpha = 1.0
    if parts[3]:
        alpha = float(parts[3][:-1]) / 100 if parts[3].endswith("%") else float(parts[3])
    return channels, alpha


def role_for(prop):
    if prop in BACKGROUND:
        return "background"
    if prop in TEXT:
        return "text"
    if prop in FILL:
        return "fill"
    if prop in SHADOW:
        return "shadow"
    return "line"


# Brand/accent tokens double as fills (buttons, active nav) and as text or
# hairline accents. Fills keep a brand-derived token; text and lines switch
# to a lifted accent that stays readable on dark surfaces.
ACCENT_VAR = re.compile(r"var\(--(green-dark|brand-teal-strong|green|brand-teal|brand-primary|ai-accent)(?![-\w])(?:[^()]|\([^()]*\))*\)")
FILL_VAR = re.compile(r"var\(--(green|green-dark|brand-teal|brand-teal-strong|brand-primary|brand-amber|brand-accent|ai-accent|ai-amber|ai-grad|red)(?![-\w])")


def _accent(match):
    strong = match.group(1) in {"green-dark", "brand-teal-strong"}
    return "var(--dk-accent-strong)" if strong else "var(--dk-accent)"


def remap_value(prop, value, on_fill=False):
    role = role_for(prop)
    if on_fill and role == "text":
        return value  # text drawn on a fill that keeps its color
    if role in ("text", "fill", "line", "shadow"):
        value = ACCENT_VAR.sub(_accent, value)
    return COLOR.sub(lambda match: _format(*remap(*_parse(match), role)), value)


def has_fill(pairs):
    """True when the rule paints its own background with a color the dark
    theme keeps (a saturated literal or a brand fill token)."""
    for prop, value in pairs:
        if prop not in BACKGROUND or "gradient(" in value and "var(" not in value and not COLOR.search(value):
            continue
        if FILL_VAR.search(value):
            return True
        colors = [_parse(match) for match in COLOR.finditer(value)]
        if colors and all(remap(rgb, alpha, "background") == (rgb, alpha) and alpha >= 0.5 for rgb, alpha in colors):
            return True
    return False


# --- CSS walking ----------------------------------------------------------

def strip_comments(css):
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def blocks(css):
    """Yields (prelude, body) for each top-level block, honoring nesting."""
    position, length = 0, len(css)
    while position < length:
        brace = css.find("{", position)
        if brace < 0:
            return
        prelude = css[position:brace].strip()
        depth, cursor, quote = 1, brace + 1, None
        while cursor < length and depth:
            char = css[cursor]
            if quote:
                if char == quote and css[cursor - 1] != "\\":
                    quote = None
            elif char in "\"'":
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            cursor += 1
        # Statements such as @import end in ";" before the next block.
        if ";" in prelude and prelude.startswith("@"):
            prelude = prelude.rsplit(";", 1)[-1].strip()
        yield prelude, css[brace + 1:cursor - 1]
        position = cursor


def declarations(body):
    parts, depth, current, quote = [], 0, "", None
    for char in body:
        if quote:
            current += char
            if char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == ";" and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    parts.append(current)
    for part in parts:
        if ":" in part:
            prop, value = part.split(":", 1)
            yield prop.strip().lower(), value.strip()


def split_selectors(prelude):
    parts, depth, current = [], 0, ""
    for char in prelude:
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        if char == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += char
    parts.append(current.strip())
    return [part for part in parts if part]


def scope_selector(selector):
    if selector.startswith(":root"):
        return SCOPE + selector[len(":root"):]
    if re.match(r"html(?![-\w])", selector):
        # html[dir=rtl] .x  ->  html.theme-dark[dir=rtl] .x
        return "html.theme-dark" + selector[4:]
    return f"{SCOPE} {selector}"


def convert(css):
    out = []
    for prelude, body in blocks(strip_comments(css)):
        lowered = prelude.lower()
        if lowered.startswith(("@keyframes", "@-webkit-keyframes", "@font-face", "@page")):
            continue
        if lowered.startswith("@media") and re.search(r"\bprint\b", lowered) and "screen" not in lowered:
            continue  # printouts stay light
        if lowered.startswith(("@media", "@supports", "@layer", "@container")):
            inner = convert(body)
            if inner:
                out.append(prelude + "{" + "".join(inner) + "}")
            continue
        if lowered.startswith("@starting-style"):
            continue
        pairs = [(prop, value) for prop, value in declarations(body)
                 if not CUSTOM_PROPERTY.match(prop) and prop in PROPERTIES]
        on_fill = has_fill(pairs)
        kept = [f"{prop}:{remap_value(prop, value, on_fill)}" for prop, value in pairs]
        if kept:
            selectors = ",".join(scope_selector(selector) for selector in split_selectors(prelude))
            out.append(selectors + "{" + ";".join(kept) + "}\n")
    return out


# Hand-tuned tokens and fixes, applied after the generated rules.
DARK_TOKENS = """
/* Theme tokens. The configured brand color stays the identity color of the
   sidebar and filled buttons; accents used as text are lifted toward white so
   they stay readable on dark surfaces whatever brand color is configured. */
html.theme-dark{color-scheme:dark;
  --bg:#0f151a;--white:#182128;--ink:#e3e9ec;--muted:#9aa9b2;--line:#2c3840;--nav:#0b1115;
  --red:#ff8a80;--shadow:0 1px 3px rgba(0,0,0,.45);
  --brand-teal-strong:color-mix(in oklab,var(--brand-primary,#003e4c) 70%,#000);
  --brand-teal-soft:color-mix(in oklab,var(--brand-primary,#003e4c) 30%,#182128);
  --brand-amber-soft:color-mix(in oklab,var(--brand-accent,#f9aa3c) 18%,#182128);
  --green:color-mix(in oklab,var(--brand-primary,#003e4c) 62%,#2fb59b);
  --green-dark:color-mix(in oklab,var(--brand-primary,#003e4c) 78%,#2fb59b);
  --dk-accent:color-mix(in oklab,var(--brand-primary,#003e4c) 30%,#8fe3d1);
  --dk-accent-strong:color-mix(in oklab,var(--brand-primary,#003e4c) 18%,#a9ecdd);
  --border:#2c3840}
html.theme-dark body .ai-run,html.theme-dark body .ai-chat{--ai-soft:var(--brand-teal-soft);
  --ai-accent:color-mix(in oklab,var(--brand-primary,#003e4c) 62%,#2fb59b);
  --ai-accent-light:color-mix(in oklab,var(--brand-primary,#003e4c) 40%,#3fc4aa)}
html.theme-dark body.high-contrast{--bg:#05080a;--white:#0f1519;--ink:#fff;--muted:#d0dade;--line:#7d8d95;
  --dk-accent:#9df0de;--dk-accent-strong:#c2f7ec}
html.theme-dark body{background:var(--bg);color:var(--ink)}
html.theme-dark ::selection{background:color-mix(in oklab,var(--green) 40%,transparent)}
"""


def build():
    pieces = [
        "/* Generated by tools/build_dark_theme.py from the light stylesheets; do not edit by hand. */\n",
        "/* Applied when the signed-in user picks the dark theme (or the system theme in dark mode). */\n",
    ]
    for name in SOURCES:
        rules = convert((STATIC / name).read_text(encoding="utf-8"))
        if rules:
            pieces.append(f"/* {name} */\n")
            pieces.extend(rules)
    overrides = STATIC / "dark-overrides.css"
    pieces.append(DARK_TOKENS.lstrip("\n"))
    if overrides.exists():
        pieces.append("/* dark-overrides.css */\n")
        pieces.append(overrides.read_text(encoding="utf-8"))
    return "".join(pieces)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="fail if static/dark.css is out of date")
    args = parser.parse_args()
    css = build()
    if args.check:
        if not TARGET.exists() or TARGET.read_text(encoding="utf-8") != css:
            print("static/dark.css is out of date: run tools/build_dark_theme.py", file=sys.stderr)
            return 1
        return 0
    TARGET.write_text(css, encoding="utf-8")
    print(f"wrote {TARGET.relative_to(ROOT)} ({len(css)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
