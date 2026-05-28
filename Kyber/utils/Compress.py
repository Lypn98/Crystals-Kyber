
"""
Kyber の係数圧縮（Compress_q）とビットパックの正確実装。

- compress_coeff(x, q, d): 係数 x を d ビットへ量子化（Kyber 公式式）
- compress_poly(poly, d, q): 多項式（長さ n=256）を d ビット値のリストへ
- compress_polyvec(polyvec, d, q): ベクトル（長さ k）をまとめて処理
- pack_bits(values, d): d ビット値列を LSB-first でバイト列にパック
- pack_poly(poly, d, q): 多項式を圧縮してバイト列へ
- pack_polyvec(polyvec, d, q): ベクトル（k 本）を圧縮して連結バイト列へ
"""

from typing import List

Q_DEFAULT = 3329
N_DEFAULT = 256

def compress_coeff(x: int, q: int = Q_DEFAULT, d: int = 10) -> int:
    """
    v = floor( ((x mod q) * 2^d + q/2) / q ) & ((1<<d)-1)
    返り値は d ビットの整数（0..2^d-1）。
    """
    x_mod = x % q
    v = ((x_mod << d) + (q // 2)) // q
    return v & ((1 << d) - 1)

def compress_poly(poly: List[int], d: int, q: int = Q_DEFAULT) -> List[int]:
    """多項式（長さ 256）を d ビット値列へ量子化。"""
    return [compress_coeff(c, q=q, d=d) for c in poly]

def compress_polyvec(polyvec: List[List[int]], d: int, q: int = Q_DEFAULT) -> List[List[int]]:
    """ベクトル（k 本の多項式）をまとめて量子化。"""
    return [compress_poly(p, d=d, q=q) for p in polyvec]

# ---------------- Bit packing (LSB-first) ----------------

def pack_bits(values: List[int], d: int) -> bytes:
    """
    d ビット値列を LSB-first（下位ビットから詰める）で連続バイトへパック。
    Decompress 側の unpack_bits と 1:1 に対応。
    """
    out = bytearray()
    acc = 0
    acc_bits = 0
    mask = (1 << d) - 1
    for v in values:
        v &= mask
        acc |= (v << acc_bits)
        acc_bits += d
        while acc_bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            acc_bits -= 8
    if acc_bits > 0:
        out.append(acc & 0xFF)
    return bytes(out)

def pack_poly(poly: List[int], d: int, q: int = Q_DEFAULT) -> bytes:
    """1本の多項式を圧縮＋ビットパックしてバイト列へ。"""
    return pack_bits(compress_poly(poly, d=d, q=q), d=d)

def pack_polyvec(polyvec: List[List[int]], d: int, q: int = Q_DEFAULT) -> bytes:
    """ベクトル（k 本）を圧縮＋各多項式を連結してバイト列へ。"""
    parts = [pack_poly(p, d=d, q=q) for p in polyvec]
    return b''.join(parts)
