#!/usr/bin/env python3
"""Phone Vault printable backup card: a blank, one-page template the user fills in BY HAND.

The card carries no secret and no per-wallet data: it is the same file for everyone. It is written
here as a tiny hand-made PDF (base-14 Helvetica, vector lines, no images, no fonts embedded, no
timestamps) so the output is byte-for-byte deterministic and needs nothing but Python 3:

    python3 tools/backup-card/make_card.py          # writes tools/backup-card/out/*.pdf
    python3 tools/backup-card/make_card.py --check  # fails if the checked-in PDFs are stale

Four files: A4 and US Letter, each with a SeedQR grid in one of the two sizes a 24-word wallet can
use (SeedSigner's SeedQR spec, https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md):
  * 25 x 25 -- CompactSeedQR (32 bytes of entropy, binary mode, QR version 2, error correction L).
    This is the phone's default "Show as SeedQR" view.
  * 29 x 29 -- Standard SeedQR (96 digits, numeric mode, QR version 3, error correction L).
The grid pre-prints the QR "function patterns" (finder squares, timing lines, alignment square,
dark module), which are identical in every QR code of that version and carry no data; the user
colours in the remaining dark squares exactly as the phone shows them. The phone app's tests check
that its QR matrices have these same fixed patterns (SeedQrTest.cardPrePrintedPatternsMatchThePhone).
"""
import os
import sys
import zlib

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
PAPERS = {"a4": (595.0, 842.0), "letter": (612.0, 792.0)}
GRIDS = {"compact25": (2, "CompactSeedQR", "25 x 25"), "standard29": (3, "Standard SeedQR", "29 x 29")}
SPEC = "github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md"

# Helvetica advance widths (AFM, 1/1000 em) for ASCII 32..126; Bold is approximated as +6 %.
_W = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
      556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
      1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
      667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
      333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
      556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584]
_EXTRA = {"—": 1000, "·": 278, "•": 350, "×": 584, "…": 1000, "→": 1000}


def width(text, size, bold=False):
    w = sum(_W[ord(ch) - 32] if 32 <= ord(ch) <= 126 else _EXTRA.get(ch, 600) for ch in text)
    return w * size / 1000.0 * (1.06 if bold else 1.0)


def wrap(text, size, max_w, bold=False):
    lines, line = [], ""
    for word in text.split(" "):
        trial = word if not line else line + " " + word
        if width(trial, size, bold) <= max_w or not line:
            line = trial
        else:
            lines.append(line)
            line = word
    if line:
        lines.append(line)
    return lines


def function_patterns(version):
    """{(row, col): dark?} for the fixed QR function patterns of a version-2/3 symbol."""
    n = 17 + 4 * version
    cells = {}
    for (r0, c0) in ((0, 0), (0, n - 7), (n - 7, 0)):
        for r in range(-1, 8):
            for c in range(-1, 8):
                rr, cc = r0 + r, c0 + c
                if not (0 <= rr < n and 0 <= cc < n):
                    continue
                inside = 0 <= r <= 6 and 0 <= c <= 6
                dark = inside and (r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4))
                cells[(rr, cc)] = dark  # the one-module white separator is part of it
    for i in range(8, n - 8):
        cells[(6, i)] = i % 2 == 0
        cells[(i, 6)] = i % 2 == 0
    a = n - 7  # single alignment pattern centre for versions 2-6
    for r in range(-2, 3):
        for c in range(-2, 3):
            cells[(a + r, a + c)] = max(abs(r), abs(c)) != 1
    cells[(4 * version + 9, 8)] = True  # the "dark module"
    return n, cells


class Page:
    def __init__(self, w, h):
        self.w, self.h, self.ops = w, h, []

    def y(self, top):
        return self.h - top

    def text(self, x, top, s, size, bold=False, gray=0.0):
        enc = s.encode("cp1252")
        esc = enc.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
        self.ops.append(b"BT /%s %.2f Tf %.3f g %.2f %.2f Td (%s) Tj ET" % (
            b"F2" if bold else b"F1", size, gray, x, self.y(top), esc))

    def line(self, x1, t1, x2, t2, lw=0.5, gray=0.0):
        self.ops.append(b"%.2f w %.3f G %.2f %.2f m %.2f %.2f l S" % (lw, gray, x1, self.y(t1), x2, self.y(t2)))

    def rect(self, x, top, w, h, fill=None, stroke=None, lw=0.5):
        r = b"%.2f %.2f %.2f %.2f re" % (x, self.y(top + h), w, h)
        if fill is not None and stroke is not None:
            self.ops.append(b"%.2f w %.3f g %.3f G %s B" % (lw, fill, stroke, r))
        elif fill is not None:
            self.ops.append(b"%.3f g %s f" % (fill, r))
        else:
            self.ops.append(b"%.2f w %.3f G %s S" % (lw, stroke, r))


def card(paper, grid):
    pw, ph = PAPERS[paper]
    version, grid_name, grid_size = GRIDS[grid]
    p = Page(pw, ph)
    m = 40.0
    right = pw - m

    # --- header
    p.text(m, 52, "PHONE VAULT · RECOVERY BACKUP CARD", 15, bold=True)
    tag = "SECRET ONCE FILLED IN"
    tw = width(tag, 8, True)
    p.rect(right - tw - 12, 38, tw + 12, 18, fill=0.0)
    p.text(right - tw - 6, 50.5, tag, 8, bold=True, gray=1.0)
    p.text(m, 70, "Fill in by hand, in pen. Blank, this card holds nothing; written on, it IS your wallet.", 9, gray=0.25)

    # --- identification fields (all public, non-secret)
    top = 100
    p.text(m, top, "Date written", 8, bold=True, gray=0.3)
    p.line(m, top + 18, m + 110, top + 18, 0.6)
    x = m + 130
    p.text(x, top, "Account 1 address (to tell cards apart — public)", 8, bold=True, gray=0.3)
    p.text(x, top + 16, "0x", 11)
    p.line(x + 15, top + 18, x + 85, top + 18, 0.6)
    p.text(x + 90, top + 16, "…", 11)
    p.line(x + 105, top + 18, x + 175, top + 18, 0.6)
    p.text(x + 15, top + 27, "first 4 after 0x", 6, gray=0.45)
    p.text(x + 105, top + 27, "last 4", 6, gray=0.45)
    x2 = x + 200
    p.text(x2, top, "Copy", 8, bold=True, gray=0.3)
    p.text(x2, top + 16, "1  /  2", 11)
    p.text(x2, top + 27, "circle one", 6, gray=0.45)

    # --- 24 word lines in two columns
    top = 150
    p.text(m, top, "RECOVERY WORDS · 24 WORDS, IN ORDER", 9, bold=True)
    col_w = (right - m - 24) / 2
    row_h = 21.0 if ph > 800 else 19.0
    for i in range(24):
        col, row = divmod(i, 12)
        cx = m + col * (col_w + 24)
        base = top + 26 + row * row_h
        p.text(cx, base, "%02d" % (i + 1), 10, bold=True, gray=0.35)
        p.line(cx + 22, base + 2, cx + col_w, base + 2, 0.6, 0.15)
    words_end = top + 26 + 11 * row_h + 10

    # --- SeedQR grid (right) and instructions (left)
    n, fixed = function_patterns(version)
    label = 12.0
    gtop = words_end + 34
    # as large as the page allows (bigger squares are easier to colour), leaving room for the footer
    cell = min({25: 11.0, 29: 9.6}[n], (ph - 62 - gtop - label) / n)
    gw = label + n * cell
    gx = right - gw
    p.text(gx, gtop - 14, "SEEDQR (OPTIONAL) · %s · %s" % (grid_name.upper(), grid_size.replace(" x ", " × ")), 8, bold=True)
    ox, oy = gx + label, gtop + label
    fs = 5.4 if n == 29 else 5.8
    for i in range(n):
        s = str(i + 1)
        p.text(ox + i * cell + (cell - width(s, fs)) / 2, gtop + label - 3.5, s, fs, gray=0.35)
        p.text(gx + label - 2.5 - width(s, fs), oy + i * cell + cell / 2 + fs * 0.36, s, fs, gray=0.35)
    for (r, c), dark in sorted(fixed.items()):
        p.rect(ox + c * cell, oy + r * cell, cell, cell, fill=0.0 if dark else 0.92)
    for i in range(n + 1):
        major = i % 5 == 0 or i == n
        lw, g = (0.7, 0.35) if major else (0.25, 0.65)
        p.line(ox + i * cell, oy, ox + i * cell, oy + n * cell, lw, g)
        p.line(ox, oy + i * cell, ox + n * cell, oy + i * cell, lw, g)
    p.rect(ox, oy, n * cell, n * cell, stroke=0.0, lw=1.0)
    grid_bottom = oy + n * cell

    iw = gx - m - 18
    tips = [
        ("Write", "the 24 words from the phone in order, one per line. Print clearly and check each spelling against the phone."),
        ("Never", "photograph, scan, type, copy-paste or store a filled-in card on any computer, phone or cloud. Nothing on this card is ever entered anywhere but the phone itself."),
        ("Two copies,", "kept in two separate safe places (think fire, flood and theft). Anyone who reads either copy controls the wallet."),
        ("No passphrase here.", "If you add a passphrase, it is not on this card: store it separately. The words alone open a different, empty wallet."),
        ("SeedQR grid:", "optional. On the phone: Security > Show as SeedQR. Fill every dark square; the black and grey squares are pre-printed and are the same in every code of this size. It encodes the same 24 words, so it is just as secret."),
        ("Check it", "every few months: Security > Check my backup asks for 3 words from this card. It takes two minutes."),
    ]
    t = gtop - 14
    p.text(m, t, "HOW TO USE THIS CARD", 8, bold=True)
    t += 16
    for head, body in tips:
        lines = wrap(head + " " + body, 8.2, iw - 10)
        p.text(m, t, "•", 8.2)
        first = True
        for ln in lines:
            if first and ln.startswith(head):
                p.text(m + 10, t, head, 8.2, bold=True)
                p.text(m + 10 + width(head + " ", 8.2, True), t, ln[len(head) + 1:], 8.2)
            else:
                p.text(m + 10, t, ln, 8.2)
            first = False
            t += 10.6
        t += 4
    footer = max(grid_bottom, t) + 26
    foot = ("Phone Vault backup card (%s, %s grid). SeedQR format: SeedSigner specification, %s. "
            "This template carries no wallet data and is identical for every user." % (paper.upper() if paper == "a4" else "US Letter", grid_size.replace(" x ", "×"), SPEC))
    for ln in wrap(foot, 6.5, right - m):
        p.text(m, footer, ln, 6.5, gray=0.45)
        footer += 8.5
    if footer > ph - 20:
        raise SystemExit("layout overflow on %s/%s" % (paper, grid))
    return p


def pdf(page, title):
    stream = zlib.compress(b"\n".join(page.ops), 9)
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> /Contents 4 0 R >>" % (page.w, page.h),
        b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        b"<< /Title (%s) /Producer (tools/backup-card/make_card.py) >>" % title.encode("ascii"),
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info 7 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


def build():
    files = {}
    for paper in PAPERS:
        for grid in GRIDS:
            name = "phone-vault-backup-card-%s-%s.pdf" % (paper, grid)
            files[name] = pdf(card(paper, grid), "Phone Vault backup card")
    return files


def main():
    files = build()
    if "--check" in sys.argv:
        stale = [n for n, data in files.items()
                 if not os.path.exists(os.path.join(OUT, n)) or open(os.path.join(OUT, n), "rb").read() != data]
        if stale:
            raise SystemExit("stale backup cards (run make_card.py): " + ", ".join(stale))
        print("backup cards up to date")
        return
    os.makedirs(OUT, exist_ok=True)
    for name, data in files.items():
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(data)
        print("wrote", os.path.join("tools/backup-card/out", name), len(data), "bytes")


if __name__ == "__main__":
    main()
