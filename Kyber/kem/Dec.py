from __future__ import annotations

from typing import Dict, List

from Kyber.utils.Decompress import unpack_polyvec, unpack_poly
from Kyber.utils.NTT import Q, N, to_ntt, from_ntt, poly_basemul_montgomery, poly_reduce
from Kyber.utils.Encode import unpack_sk
from Kyber.utils.Compress import compress_coeff


def Dec(ct: bytes, sk_bytes: bytes, P: Dict) -> bytes:
    """CPAPKE.Dec aligned to kyber-py-main representation."""
    k = P["k"]
    du = P["du"]
    dv = P["dv"]

    c1_len = ((N * du + 7) // 8) * k
    c1, c2 = ct[:c1_len], ct[c1_len:]

    u_vec = unpack_polyvec(c1, k=k, d=du, q=Q)
    v = unpack_poly(c2, d=dv, q=Q)

    s_hat = unpack_sk(sk_bytes, k)

    u_hat = [to_ntt(poly) for poly in u_vec]
    acc = [0] * N
    for j in range(k):
        prod = poly_basemul_montgomery(s_hat[j], u_hat[j])
        acc = [(acc[c] + prod[c]) % Q for c in range(N)]
    inner = from_ntt(acc)

    w = [(v[c] - inner[c]) % Q for c in range(N)]
    w = poly_reduce(w)

    out = bytearray(32)
    for i in range(32):
        byte = 0
        for b in range(8):
            coeff = w[8 * i + b]
            bit = compress_coeff(coeff, q=Q, d=1)
            byte |= (bit << b)
        out[i] = byte
    return bytes(out)
