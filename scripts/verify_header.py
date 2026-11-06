#!/usr/bin/env python3
"""Verify the baked header lettering without eyeballing it.

Two checks per file (assets/apse-header.svg, assets/apse-header-tagline.svg):

1. winding — every contour *nested* inside another contour's bbox (a
   counter, i.e. a hole) must wind the opposite way from its container:
   that is what keeps the SVG nonzero fill rule from filling the
   counters in, or (the user-visible failure: "the fill is outside the
   letter shape") from filling everything except the letter. Disjoint
   contours (an i's dot) may wind either way, so only nested pairs are
   checked (LESSONS #50).

2. raster — render the files' own lettering paths with an SVG rasterizer
   (RSVG, via ImageMagick) and compare pixel-for-pixel against FreeType
   (Pillow) rendering the real font at the exact geometry the baker
   used (scripts/bake_header.py). The two rasterizers differ only at
   the subpixel fringe: a correct bake lands at ~0.6% diff and high
   ink IoU (91% for the 40 px wordmark, ~75% for the 10 px tagline —
   the 1 px fringe is a large fraction of a small glyph). The
   tolerances are calibrated against the real failure mode (the
   all_cubic=False bake that dropped qCurveTo segments, LESSONS #50):
   broken wordmark 5.3% diff / 33% IoU, broken tagline 0.8% diff /
   58% IoU. Note that diff alone does not catch the small-glyph case
   (0.8% vs 0.4% for the tagline) — IoU is the gate that separates.

    python3 scripts/verify_header.py

Requires fontTools, Pillow, and ImageMagick with the RSVG delegate
(`magick -list format | grep -i svg`). Exits non-zero on failure.
"""

import os
import re
import subprocess
import sys
import tempfile
from PIL import Image, ImageDraw, ImageFont
from fontTools.ttLib import TTFont

import bake_header as bk

DIFF_TOL = 0.03   # max fraction of canvas pixels that may differ
IOU_TOL = 0.65    # min ink IoU (see docstring for the calibration)


def parse_d(d):
    out = []
    pat = (r"([MLC])(-?\d+\.?\d+\s+-?\d+\.?\d+"
           r"(?:\s+-?\d+\.?\d+\s+-?\d+\.?\d+\s+-?\d+\.?\d+\s+-?\d+\.?\d+)?)\s*|Z")
    for m in re.finditer(pat, d):
        if m.group(1):
            nums = [float(x) for x in re.findall(r"-?\d+\.?\d+", m.group(2))]
            out.append((m.group(1),
                        [(nums[i], nums[i+1]) for i in range(0, len(nums), 2)]))
        else:
            out.append(("Z", None))
    return out


def sampled_pts(cmds):
    pts = [cmds[0][1][0]]
    for c, seg in cmds[1:]:
        if c == "L":
            pts.append(seg[0])
        elif c == "C":
            p0 = pts[-1]
            for k in range(1, 33):
                t = k/32
                u = 1-t
                pts.append((u**3*p0[0] + 3*u*u*t*seg[0][0] + 3*u*t*t*seg[1][0]
                            + t**3*seg[2][0],
                            u**3*p0[1] + 3*u*u*t*seg[0][1] + 3*u*t*t*seg[1][1]
                            + t**3*seg[2][1]))
    return pts


def contour_area(pts):
    a = 0.0
    for i in range(len(pts)):
        x0, y0 = pts[i]
        x1, y1 = pts[(i+1) % len(pts)]
        a += x0*y1 - x1*y0
    return a/2


def contour_bbox(pts):
    return (min(x for x, _ in pts), min(y for _, y in pts),
            max(x for x, _ in pts), max(y for _, y in pts))


def glyph_contours(d):
    groups, cur = [], []
    for c, pts in parse_d(d):
        cur.append((c, pts))
        if c == "Z":
            groups.append(cur)
            cur = []
    return groups


def enclosed(a, b, tol=1.0):
    return (b[0] - tol <= a[0] and b[1] - tol <= a[1]
            and a[2] <= b[2] + tol and a[3] <= b[3] + tol)


def winding_check(paths):
    """Same-sign nested contours are a nonzero-fill bug."""
    bad = []
    for cls, d in paths:
        cs = glyph_contours(d)
        pts = [sampled_pts(c) for c in cs]
        areas = [contour_area(p) for p in pts]
        bbs = [contour_bbox(p) for p in pts]
        for i, j in enumerate(range(len(cs))):
            if i == j:
                continue
            if enclosed(bbs[i], bbs[j]) and enclosed(bbs[j], bbs[i]):
                continue  # coincident (should not happen)
            if (enclosed(bbs[i], bbs[j]) or enclosed(bbs[j], bbs[i])) \
                    and (areas[i] > 0) == (areas[j] > 0):
                bad.append((cls, i, j, areas[i], areas[j]))
    return bad


def main():
    ok = True

    files = [
        (bk.HEADER, "apse-header.svg",
         [(bk.WORDMARK, bk.WM_X0, bk.WM_BASELINE_PLAIN, bk.WM_XH,
           bk.WM_TRACKING)], 377),
        (bk.TAGLINE, "apse-header-tagline.svg",
         [(bk.WORDMARK, bk.WM_X0, bk.WM_BASELINE_TAGLINE, bk.WM_XH,
           bk.WM_TRACKING),
          (bk.TAGLINE_TEXT, bk.TL_X0, bk.TL_BASELINE, bk.TL_XH, 0.0)], 587),
    ]

    for file, name, groups, width in files:
        src = file.read_text()
        paths = re.findall(
            r'<path class="(wavef|tag|sub)" d="([^"]*)"/>', src)
        print(f"== {name} ==  ({len(paths)} lettering paths)")

        bad = winding_check(paths)
        if bad:
            ok = False
            for cls, i, j, ai, aj in bad:
                print(f"  WINDING: {cls} contours {i} & {j} nest but wind the "
                      f"same way ({ai:+.0f}, {aj:+.0f})")
        else:
            print("  winding: OK (every nested counter opposes its container)")

        for (text, x0, baseline, xh, tracking) in groups:
            fp = bk.FONT_BOLD if text == bk.WORDMARK else bk.FONT_REGULAR
            a, b, d, iou = raster_check_one(file, fp,
                                            (text, x0, baseline, xh,
                                             tracking), width)
            status = "OK" if (d <= DIFF_TOL and iou >= IOU_TOL) else "FAIL"
            if status == "FAIL":
                ok = False
            print(f"  raster [{text[:24]}…]: ink ft={a} rsvg={b} "
                  f"diff={100*d:.2f}% IoU={100*iou:.1f}%  {status}")

    print("RESULT:", "OK" if ok else "FAIL")
    sys.exit(0 if ok else 1)


def raster_check_one(file, font_path, group, width):
    """Compare one lettering group: the file's paths of that group's classes
    (rsvg) vs. FreeType rendering the real font at the group's geometry."""
    text, x0, baseline, xh, tracking = group
    # this group's paths: wordmark = wavef/tag, tagline = sub
    cls = "wavef|tag" if text == bk.WORDMARK else "sub"
    ds = [d for _, d in re.findall(
        rf'<path class="({cls})" d="([^"]*)"/>', file.read_text())]
    check = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 '
             f'{width} 160" width="{width}" height="160">'
             '<rect width="100%" height="100%" fill="#fff"/>'
             + "".join(f'<path fill="#000" d="{d}"/>' for d in ds)
             + "</svg>")
    with tempfile.NamedTemporaryFile("w", suffix=".svg", delete=False) as f:
        f.write(check)
        check_path = f.name
    png_path = check_path.replace(".svg", ".png")
    try:
        subprocess.run(["magick", check_path, png_path], check=True)
        got = Image.open(png_path)
    finally:
        os.unlink(check_path)
        os.unlink(png_path)

    canvas = Image.new("L", (width, 160), 255)
    dr = ImageDraw.Draw(canvas)
    scale, items = bk.layout(font_path, text, x0, baseline, xh, tracking)
    upem = TTFont(font_path)["head"].unitsPerEm
    pil = ImageFont.truetype(font_path, size=scale*upem)
    ascent = pil.getmetrics()[0]
    for item in items:
        if item is None:
            continue
        ch, ox = item
        dr.text((ox, baseline - ascent), ch, font=pil, fill=0)

    a = canvas.point(lambda v: 1 if v < 128 else 0)
    b = got.convert("L").point(lambda v: 1 if v < 128 else 0)
    pa, pb = bytes(a.tobytes()), bytes(b.tobytes())
    ink_a, ink_b = sum(pa), sum(pb)
    diff = sum(x != y for x, y in zip(pa, pb))
    inter = sum(x & y for x, y in zip(pa, pb))
    union = max(1, sum(x | y for x, y in zip(pa, pb)))
    return ink_a, ink_b, diff / len(pa), inter / union


if __name__ == "__main__":
    main()
