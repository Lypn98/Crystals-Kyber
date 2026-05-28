from __future__ import annotations

from typing import List, Tuple

# Pure Z_q NTT aligned to kyber-py-main (no Montgomery domain, no int16 wrapping).
Q: int = 3329
N: int = 256

def _br(i: int, k: int) -> int:
    b = bin(i & ((1 << k) - 1))[2:].zfill(k)
    return int(b[::-1], 2)

ROOT_OF_UNITY = 17
# zetas[0] is unused in the transform loops (k starts from 1), kept for index compatibility
ZETAS: List[int] = [pow(ROOT_OF_UNITY, _br(i, 7), Q) for i in range(128)]
F_INV: int = pow(128, -1, Q)

def poly_reduce(a: List[int]) -> List[int]:
    return [c % Q for c in a]

def ntt(coeffs: List[int]) -> List[int]:
    """
    Forward NTT.
    Input: standard order.
    Output: bit-reversed order.
    """
    a = coeffs[:]
    k, l = 1, 128
    while l >= 2:
        start = 0
        while start < N:
            zeta = ZETAS[k]
            k += 1
            j = start
            for j in range(start, start + l):
                t = zeta * a[j + l]
                a[j + l] = a[j] - t
                a[j] = a[j] + t
            start = l + (j + 1)
        l >>= 1
    return [x % Q for x in a]

def inv_ntt(coeffs: List[int]) -> List[int]:
    """
    Inverse NTT.
    Input: bit-reversed order.
    Output: standard order.
    """
    a = coeffs[:]
    l, l_upper = 2, 128
    k = l_upper - 1
    while l <= 128:
        start = 0
        while start < N:
            zeta = ZETAS[k]
            k -= 1
            j = start
            for j in range(start, start + l):
                t = a[j]
                a[j] = t + a[j + l]
                a[j + l] = a[j + l] - t
                a[j + l] = zeta * a[j + l]
            start = j + l + 1
        l <<= 1
    for j in range(N):
        a[j] = (a[j] * F_INV) % Q
    return a

def to_ntt(a: List[int]) -> List[int]:
    return ntt(a)

def from_ntt(a_ntt: List[int]) -> List[int]:
    return inv_ntt(a_ntt)

def _ntt_base_multiplication(a0: int, a1: int, b0: int, b1: int, zeta: int) -> Tuple[int, int]:
    r0 = (a0 * b0 + zeta * a1 * b1) % Q
    r1 = (a1 * b0 + a0 * b1) % Q
    return r0, r1

def poly_basemul_montgomery(a_ntt: List[int], b_ntt: List[int]) -> List[int]:
    """
    Pointwise multiplication in NTT domain using Kyber's base multiplication.
    Name kept for compatibility with existing code.
    """
    out = [0] * N
    for i in range(64):
        z = ZETAS[64 + i]
        r0, r1 = _ntt_base_multiplication(
            a_ntt[4*i + 0], a_ntt[4*i + 1],
            b_ntt[4*i + 0], b_ntt[4*i + 1],
            z
        )
        r2, r3 = _ntt_base_multiplication(
            a_ntt[4*i + 2], a_ntt[4*i + 3],
            b_ntt[4*i + 2], b_ntt[4*i + 3],
            (-z) % Q
        )
        out[4*i + 0] = r0
        out[4*i + 1] = r1
        out[4*i + 2] = r2
        out[4*i + 3] = r3
    return out

def polymul_ntt(a: List[int], b: List[int]) -> List[int]:
    a_ntt = to_ntt(a)
    b_ntt = to_ntt(b)
    c_ntt = poly_basemul_montgomery(a_ntt, b_ntt)
    c = from_ntt(c_ntt)
    return poly_reduce(c)

def polymul_naive(a: List[int], b: List[int]) -> List[int]:
    res = [0] * N
    for i in range(N):
        ai = a[i] % Q
        for j in range(N):
            t = ai * (b[j] % Q)
            k = i + j
            if k < N:
                res[k] += t
            else:
                res[k - N] -= t
    return [x % Q for x in res]
