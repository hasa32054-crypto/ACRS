"""Minimal QR Code encoder (ISO/IEC 18004), pure Python: byte mode, error correction level M, versions 1-10
(up to 213 bytes). Written because the booth must work offline with no third-party packages.
Verified in tests by decoding with OpenCV's QRCodeDetector when it is installed.
"""
from __future__ import annotations

# version -> (ec codewords per block, [(blocks, data codewords per block), ...])   level M
_M = {1: (10, [(1, 16)]), 2: (16, [(1, 28)]), 3: (26, [(1, 44)]), 4: (18, [(2, 32)]), 5: (24, [(2, 43)]),
      6: (16, [(4, 27)]), 7: (18, [(4, 31)]), 8: (22, [(2, 38), (2, 39)]), 9: (22, [(3, 36), (2, 37)]),
      10: (26, [(4, 43), (1, 44)])}
_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42],
          9: [6, 26, 46], 10: [6, 28, 50]}
_EC_LEVEL_M = 0b00

# ------------------------------------------------------------------ GF(256) Reed-Solomon ----------------------------
_EXP, _LOG = [0] * 512, [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x; _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _generator(n):
    g = [1]
    for i in range(n):
        g = [a ^ _mul(b, _EXP[i]) for a, b in zip(g + [0], [0] + g)]
    return g


def _ec(data, n):
    gen = _generator(n)
    res = list(data) + [0] * n
    for i in range(len(data)):
        c = res[i]
        if c:
            for j in range(1, len(gen)):
                res[i + j] ^= _mul(gen[j], c)
    return res[len(data):]


# ------------------------------------------------------------------ data codewords ----------------------------------
def _capacity(v):
    return sum(b * d for b, d in _M[v][1])


def _codewords(data: bytes, v: int):
    cc = 8 if v < 10 else 16
    bits = [0, 1, 0, 0] + [(len(data) >> i) & 1 for i in range(cc - 1, -1, -1)]
    for byte in data:
        bits += [(byte >> i) & 1 for i in range(7, -1, -1)]
    cap = _capacity(v) * 8
    bits += [0] * min(4, cap - len(bits))
    bits += [0] * (-len(bits) % 8)
    cw = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = [0xEC, 0x11]
    while len(cw) < _capacity(v):
        cw.append(pad[(len(cw) - len(bits) // 8) % 2])
    ecn, groups = _M[v]
    blocks, k = [], 0
    for nb, nd in groups:
        for _ in range(nb):
            blocks.append(cw[k:k + nd]); k += nd
    ecs = [_ec(b, ecn) for b in blocks]
    out = []
    for i in range(max(len(b) for b in blocks)):
        out += [b[i] for b in blocks if i < len(b)]
    for i in range(ecn):
        out += [e[i] for e in ecs]
    return out


# ------------------------------------------------------------------ matrix ------------------------------------------
def _bch(value, poly, length):
    v = value << (poly.bit_length() - 1)
    while v.bit_length() >= poly.bit_length():
        v ^= poly << (v.bit_length() - poly.bit_length())
    return (value << (poly.bit_length() - 1)) | v


def _format_bits(mask):
    return _bch((_EC_LEVEL_M << 3) | mask, 0b10100110111, 10) ^ 0b101010000010010


def _version_bits(v):
    return _bch(v, 0b1111100100101, 12)


_MASKS = [lambda r, c: (r + c) % 2 == 0, lambda r, c: r % 2 == 0, lambda r, c: c % 3 == 0,
          lambda r, c: (r + c) % 3 == 0, lambda r, c: (r // 2 + c // 3) % 2 == 0,
          lambda r, c: (r * c) % 2 + (r * c) % 3 == 0, lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
          lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0]


def _base(v):
    n = 17 + 4 * v
    m = [[None] * n for _ in range(n)]

    def finder(r, c):
        for i in range(-1, 8):
            for j in range(-1, 8):
                if 0 <= r + i < n and 0 <= c + j < n:
                    on = (0 <= i <= 6 and j in (0, 6)) or (0 <= j <= 6 and i in (0, 6)) or (2 <= i <= 4 and 2 <= j <= 4)
                    m[r + i][c + j] = on
    finder(0, 0); finder(0, n - 7); finder(n - 7, 0)
    for i in range(8, n - 8):
        m[6][i] = m[i][6] = i % 2 == 0
    pos = _ALIGN[v]
    last = len(pos) - 1
    for a, r in enumerate(pos):
        for b, c in enumerate(pos):
            if (a, b) in ((0, 0), (0, last), (last, 0)):                  # the three finder corners
                continue
            for i in range(-2, 3):
                for j in range(-2, 3):
                    m[r + i][c + j] = max(abs(i), abs(j)) != 1
    m[n - 8][8] = True                                                    # dark module
    for i in range(9):                                                    # reserve format areas
        for (r, c) in ((8, i), (i, 8)):
            if m[r][c] is None:
                m[r][c] = False
    for i in range(8):
        if m[8][n - 1 - i] is None:
            m[8][n - 1 - i] = False
        if m[n - 1 - i][8] is None:
            m[n - 1 - i][8] = False
    if v >= 7:
        for i in range(6):
            for j in range(3):
                m[i][n - 11 + j] = m[n - 11 + j][i] = False
    return m


def _place(m, cw, v):
    n = len(m)
    fixed = [[x is not None for x in row] for row in m]
    bits = [(b >> i) & 1 for b in cw for i in range(7, -1, -1)]
    k, up, c = 0, True, n - 1
    while c > 0:
        if c == 6:
            c -= 1
        for rr in range(n):
            r = n - 1 - rr if up else rr
            for cc in (c, c - 1):
                if not fixed[r][cc]:
                    m[r][cc] = bool(bits[k]) if k < len(bits) else False
                    k += 1
        up = not up
        c -= 2
    return fixed


def _finish(m, fixed, mask, v):
    n = len(m)
    out = [row[:] for row in m]
    for r in range(n):
        for c in range(n):
            if not fixed[r][c] and _MASKS[mask](r, c):
                out[r][c] = not out[r][c]
    f = _format_bits(mask)
    for i in range(15):                                                    # bit i (0 = least significant)
        b = bool((f >> i) & 1)
        r1, c1 = ((i, 8) if i < 6 else (7, 8) if i == 6 else (8, 8) if i == 7 else (8, 7) if i == 8 else (8, 14 - i))
        out[r1][c1] = b
        r2, c2 = (8, n - 1 - i) if i < 8 else (n - 15 + i, 8)
        out[r2][c2] = b
    out[n - 8][8] = True
    if v >= 7:
        vb = _version_bits(v)
        for i in range(18):
            b = bool((vb >> i) & 1)
            out[i // 3][n - 11 + i % 3] = b
            out[n - 11 + i % 3][i // 3] = b
    return out


def _penalty(m):
    n, s = len(m), 0
    for rows in (m, [list(x) for x in zip(*m)]):
        for row in rows:
            run = 1
            for i in range(1, n):
                if row[i] == row[i - 1]:
                    run += 1
                else:
                    s += run - 2 if run >= 5 else 0; run = 1
            s += run - 2 if run >= 5 else 0
            for i in range(n - 6):
                if row[i:i + 7] == [True, False, True, True, True, False, True]:
                    s += 40
    for r in range(n - 1):
        for c in range(n - 1):
            if m[r][c] == m[r][c + 1] == m[r + 1][c] == m[r + 1][c + 1]:
                s += 3
    dark = sum(map(sum, m)) * 100 // (n * n)
    s += abs(dark - 50) // 5 * 10
    return s


def encode(text: str | bytes) -> list[list[bool]]:
    data = text.encode("utf-8") if isinstance(text, str) else text
    for v in range(1, 11):
        header = 4 + (8 if v < 10 else 16)
        if header + 8 * len(data) <= _capacity(v) * 8:
            break
    else:
        raise ValueError("text too long for QR versions 1-10 (max 213 bytes)")
    cw = _codewords(data, v)
    m = _base(v)
    fixed = _place(m, cw, v)
    best = min(range(8), key=lambda k: _penalty(_finish(m, fixed, k, v)))
    return _finish(m, fixed, best, v)


def svg(text: str, scale: int = 6, quiet: int = 4, dark: str = "#000", light: str = "#fff") -> str:
    m = encode(text)
    n = len(m) + 2 * quiet
    path = "".join(f"M{c + quiet},{r + quiet}h1v1h-1z" for r, row in enumerate(m) for c, on in enumerate(row) if on)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {n} {n}" width="{n * scale}" height="{n * scale}" '
            f'shape-rendering="crispEdges" role="img"><rect width="{n}" height="{n}" fill="{light}"/>'
            f'<path d="{path}" fill="{dark}"/></svg>')
