#!/usr/bin/env python3
"""Bake the header SVG lettering: assets/apse-header.svg and
assets/apse-header-tagline.svg.

The lettering is a *snapshot of a font*: one <path> per glyph, no <text>
anywhere (LESSONS #49). Rewording the wordmark or tagline — or renaming
the project again — means re-running this script, never hand-editing
path data.

Fonts: Open Sans Bold (wordmark) / Regular (tagline) — the closest
installed match to the original lettering's metrics (LESSONS #49).
Override with APSE_FONT_BOLD / APSE_FONT_REGULAR for other setups.

Geometry (viewBox units, y-down, baseline-anchored):
  wordmark 'apse'   Bold, x-height 40, tracking 4, ink-left 172.49,
                    baseline 82 (tagline file) / 95.59 (plain header)
  tagline           Regular, x-height 10.16, no tracking, ink-left
                    176.06, baseline 122.90
  colors: a,p = wavef (teal), s,e = tag (amber); tagline = sub (grey)

The logo mark group is taken verbatim from the existing files (it must
be identical in both), so the script only ever replaces lettering.

    python3 scripts/bake_header.py        # requires fontTools
    python3 scripts/verify_header.py      # check the result

Baking notes:
  * Qu2CuPen must run with all_cubic=True: the default leaves qCurveTo
    segments in place, and SVG path data has no quadratic syntax — a
    recorder that drops them silently breaks every contour (LESSONS #50).
  * The y-flip (yy = -scale) reverses every contour's winding uniformly;
    nonzero fill only cares about *relative* winding (outer vs. its
    counters), which the flip preserves, so no per-contour reversal is
    needed.
"""

import math
import os
from pathlib import Path

from fontTools.pens.recordingPen import RecordingPen
from fontTools.pens.qu2cuPen import Qu2CuPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

ASSETS = Path(__file__).resolve().parent.parent / "assets"
HEADER = ASSETS / "apse-header.svg"
TAGLINE = ASSETS / "apse-header-tagline.svg"

FONT_BOLD = os.environ.get("APSE_FONT_BOLD", "/usr/share/fonts/open-sans/OpenSans-Bold.ttf")
FONT_REGULAR = os.environ.get("APSE_FONT_REGULAR",
                               "/usr/share/fonts/open-sans/OpenSans-Regular.ttf")

WORDMARK = "apse"
TAGLINE_TEXT = "unprivileged in-process sandbox for Wayland"

# Geometry constants (see module docstring).
WM_X0, WM_XH, WM_TRACKING = 172.49, 40.0, 4.0
WM_BASELINE_TAGLINE = 82.0     # wordmark baseline in the tagline file
WM_BASELINE_PLAIN = 95.59      # wordmark baseline in the plain header
TL_X0, TL_XH, TL_BASELINE = 176.06, 10.16, 122.90
PLAIN_MARGIN = 28.0            # right edge of wordmark -> file width
TAGLINE_MARGIN = 16.0          # right edge of tagline -> file width
PLAIN_MIN_WIDTH = 377
TAGLINE_MIN_WIDTH = 489

STYLE_RULES = ('.ink{stroke:#17212B;fill:none}.inkf{fill:#17212B}'
               '.wave{stroke:#2FA89A;fill:none}.wavef{fill:#2FA89A}'
               '.tag{fill:#9f6c2a}'
               '@media (prefers-color-scheme:dark){.ink{stroke:#E6EDF3}'
               '.inkf{fill:#E6EDF3}}')
STYLE_SUB_RULES = ('.sub{fill:#57606a}'
                   '@media (prefers-color-scheme:dark){.sub{fill:#9198a1}}')


def ink_bbox(gs, gname):
    """Bounding box of every point the pen reports (on-curve + controls).

    Deliberately includes control points: it is the convention the
    current assets were baked with, and for the lettering in use it is
    tight to a hair (the extremes of these glyphs are on-curve).
    """
    pen = RecordingPen()
    gs[gname].draw(pen)
    pts = [p for op, a in pen.value for p in a
           if isinstance(p, tuple) and len(p) == 2 and isinstance(p[0], (int, float))]
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    return min(xs), min(ys), max(xs), max(ys)


def layout(font_path, text, x0, baseline, xh_target, tracking=0.0):
    """Pen origins (in output units) for each character of `text`.

    Returns (scale, items): items is one entry per character — a tuple
    (char, origin_x) for letters, None for spaces — where origin_x is
    the glyph origin (the left side bearing is *not* included; a raster
    renderer adds it) and the first letter's ink starts exactly at x0.
    """
    font = TTFont(font_path)
    gs = font.getGlyphSet()
    cmap = font.getBestCmap()
    hmtx = font["hmtx"]
    xh = ink_bbox(gs, cmap[ord("x")])[3] - ink_bbox(gs, cmap[ord("x")])[1]
    scale = xh_target / xh
    items, pen_x, anchor = [], 0.0, None
    for ch in text:
        if ch == " ":
            items.append(None)
            pen_x += hmtx[cmap[ord(" ")]][0]
            continue
        g = cmap[ord(ch)]
        if anchor is None:
            anchor = ink_bbox(gs, g)[0]
        items.append((ch, x0 + (pen_x - anchor) * scale))
        pen_x += hmtx[g][0] + (tracking / scale if tracking else 0.0)
    return scale, items


def bake(font_path, text, x0, baseline, xh_target, tracking=0.0):
    """Bake `text` into one <path> per letter (cubic-only, y-down)."""
    font = TTFont(font_path)
    gs = font.getGlyphSet()
    cmap = font.getBestCmap()
    hmtx = font["hmtx"]
    xh = ink_bbox(gs, cmap[ord("x")])[3] - ink_bbox(gs, cmap[ord("x")])[1]
    scale = xh_target / xh

    glyphs, pen_x, anchor = [], 0.0, None
    for ch in text:
        if ch == " ":
            pen_x += hmtx[cmap[ord(" ")]][0]
            continue
        gname = cmap[ord(ch)]
        rec = RecordingPen()
        pen = TransformPen(Qu2CuPen(rec, 1.0, all_cubic=True),
                           (scale, 0, 0, -scale,
                            x0 + pen_x * scale, baseline))
        gs[gname].draw(pen)
        cmds = []
        for op, a in rec.value:
            assert op in ("moveTo", "lineTo", "curveTo", "closePath"), (ch, op)
            if op == "moveTo":
                cmds.append(f"M{a[0][0]:.2f} {a[0][1]:.2f}")
            elif op == "lineTo":
                cmds.append(f"L{a[0][0]:.2f} {a[0][1]:.2f}")
            elif op == "curveTo":
                cmds.append("C" + " ".join(f"{p[0]:.2f} {p[1]:.2f}" for p in a))
            else:
                cmds.append("Z")
        fb = ink_bbox(gs, gname)
        if anchor is None:
            anchor = fb[0]
        glyphs.append({"ch": ch, "d": cmds, "fb": fb, "pen": pen_x})
        pen_x += hmtx[gname][0] + (tracking / scale if tracking else 0.0)

    dx = -(anchor or 0) * scale  # re-anchor the first letter's ink-left to x0
    for g in glyphs:
        g["origin"] = x0 + (g["pen"] - anchor) * scale
        g["ink"] = (x0 + (g["pen"] + g["fb"][0]) * scale + dx,
                    baseline - g["fb"][3] * scale,
                    x0 + (g["pen"] + g["fb"][2]) * scale + dx,
                    baseline - g["fb"][1] * scale)
        out = []
        for c in g["d"]:
            if c[0] in "ML":
                n, y = c[1:].split()
                out.append(f"{c[0]}{float(n) + dx:.2f} {y}")
            elif c[0] == "C":
                nums = c[1:].split()
                nums = [f"{float(v) + dx:.2f}" if i % 2 == 0 else v
                        for i, v in enumerate(nums)]
                out.append("C" + " ".join(nums))
            else:
                out.append(c)
        g["d"] = out
    return glyphs


def emit(glyphs, classes):
    assert len(classes) == len(glyphs), (len(classes), len(glyphs))
    return [f'<path class="{c}" d="{" ".join(g["d"])}"/>'
            for g, c in zip(glyphs, classes)]


def logo_group(path):
    """The verbatim logo mark group (the first top-level <g>)."""
    s = path.read_text()
    i = s.index('<g transform="translate(16 16)">')
    depth, j = 0, i
    while True:
        n, nc = s.find("<g", j), s.find("</g>", j)
        if n != -1 and (nc == -1 or n < nc):
            depth += 1
            j = n + 2
        else:
            depth -= 1
            j = nc + 4
            if depth == 0:
                break
    return s[i:j]


def header_svg(width, logo, wm_paths):
    return "\n".join([
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} 160" '
        f'width="{width}" height="160" role="img" aria-label="apse">',
        "<title>apse</title>",
        f"<style>{STYLE_RULES}</style>",
        logo,
        *wm_paths,
        "</svg>",
    ]) + "\n"


def tagline_svg(width, logo, wm_paths, sub_paths):
    aria = f"apse — {TAGLINE_TEXT}"
    return "\n".join([
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} 160" '
        f'width="{width}" height="160" role="img" aria-label="{aria}">',
        f"<title>{aria}</title>",
        f"<style>{STYLE_RULES}{STYLE_SUB_RULES}</style>",
        logo,
        *wm_paths,
        *sub_paths,
        "</svg>",
    ]) + "\n"


def main():
    g_header = logo_group(HEADER)
    g_tagline = logo_group(TAGLINE)
    assert g_header == g_tagline, "logo groups differ between the two files"

    wm = bake(FONT_BOLD, WORDMARK, WM_X0, WM_BASELINE_TAGLINE, WM_XH, WM_TRACKING)
    wm95 = bake(FONT_BOLD, WORDMARK, WM_X0, WM_BASELINE_PLAIN, WM_XH, WM_TRACKING)
    tl = bake(FONT_REGULAR, TAGLINE_TEXT, TL_X0, TL_BASELINE, TL_XH)

    wm_right = max(g["ink"][2] for g in wm95)
    tl_right = max(g["ink"][2] for g in tl)
    plain_w = max(PLAIN_MIN_WIDTH, math.ceil(wm_right + PLAIN_MARGIN))
    tagline_w = max(TAGLINE_MIN_WIDTH, int(tl_right + TAGLINE_MARGIN))

    HEADER.write_text(header_svg(plain_w, g_header,
                                 emit(wm95, ["wavef", "wavef", "tag", "tag"])))
    TAGLINE.write_text(tagline_svg(tagline_w, g_tagline,
                                   emit(wm, ["wavef", "wavef", "tag", "tag"]),
                                   emit(tl, ["sub"] * len(tl))))

    print(f"wordmark: x {min(g['ink'][0] for g in wm):.1f}..{wm_right:.1f}")
    print(f"tagline:  x {TL_X0}..{tl_right:.1f}  "
          f"(baseline {TL_BASELINE}, xh {TL_XH})")
    print(f"wrote {HEADER} (width {plain_w}) and {TAGLINE} (width {tagline_w})")


if __name__ == "__main__":
    main()
