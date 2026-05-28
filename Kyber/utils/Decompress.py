# Kyber/utils/Decompress.py
from typing import List, Union

Q_DEFAULT = 3329
N_DEFAULT = 256

def decompress_coeff(v: int, q: int = Q_DEFAULT, d: int = 10) -> int:
    """
    Kyber 公式の Decompress_q。
    v: dビット値（0..2^d-1）
    戻り値: 復元係数（0..q-1）
    参考: 仕様書の圧縮・復元式（LSB-first パック）
    """
    return ((v * q) + (1 << (d - 1))) >> d

def _ensure_bytes(data: Union[bytes, bytearray, memoryview, List[int]]) -> bytes:
    """
    入ってくる data を必ず bytes に正規化。
    - bytes/bytearray/memoryview → bytes(data)
    - List[int]（各要素が 0..255）   → bytes(list)
    """
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    if isinstance(data, list) and all(isinstance(b, int) for b in data):
        return bytes(data)
    raise TypeError(f"_ensure_bytes: unsupported type {type(data)}")

def unpack_bits(data: Union[bytes, bytearray, memoryview, List[int]], d: int, n: int = N_DEFAULT) -> List[int]:
    """
    LSB-first でパックされた data から d ビット値を n 個取り出す。
    Kyber のパック／アンパックは LSB-first が公式（ref 実装と同じ）[2](https://github.com/pq-crystals/kyber)
    """
    data_bytes = _ensure_bytes(data)
    values: List[int] = []
    acc = 0
    acc_bits = 0
    for byte in data_bytes:                # Python3: bytes を iterate すると byte は int（0..255）
        acc |= (byte & 0xFF) << acc_bits
        acc_bits += 8
        while acc_bits >= d and len(values) < n:
            values.append(acc & ((1 << d) - 1))
            acc >>= d
            acc_bits -= d
    if len(values) != n:
        raise ValueError(f"unpack_bits: produced {len(values)} values, expected {n}")
    return values

def unpack_poly(data: Union[bytes, bytearray, memoryview, List[int]], d: int, q: int = Q_DEFAULT, n: int = N_DEFAULT) -> List[int]:
    """
    1 本の圧縮多項式（ceil(n*d/8) バイト）を復元。
    """
    vals = unpack_bits(data, d=d, n=n)                   # dビット値 n個
    return [decompress_coeff(v, q=q, d=d) for v in vals] # 係数（0..q-1）

def unpack_polyvec(data: Union[bytes, bytearray, memoryview, List[int]], d: int, q: int = Q_DEFAULT, k: int = 1, n: int = N_DEFAULT) -> List[List[int]]:
    """
    連結された k 本の圧縮多項式を順に復元。
    各多項式のバイト長は poly_bytes = ceil(n*d/8)。
    """
    data_bytes = _ensure_bytes(data)
    poly_bytes = (n * d + 7) // 8
    expected   = k * poly_bytes
    if len(data_bytes) != expected:
        raise ValueError(f"unpack_polyvec: data_len={len(data_bytes)} expected={expected}")
    out: List[List[int]] = []
    off = 0
    for _ in range(k):
        chunk = data_bytes[off:off+poly_bytes]
        out.append(unpack_poly(chunk, d=d, q=q, n=n))
        off += poly_bytes
    return out
