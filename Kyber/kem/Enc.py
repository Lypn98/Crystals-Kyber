from __future__ import annotations

from typing import Dict, List

from Kyber.utils.Hash import XOF
from Kyber.utils.Parse import parse
from Kyber.utils.CBD import sample_secret_and_noise, sample_cbd_poly
from Kyber.utils.NTT import Q, N, to_ntt, from_ntt, poly_basemul_montgomery, poly_reduce
from Kyber.utils.Encode import unpack_pk
from Kyber.utils.Compress import pack_polyvec, pack_poly


def _encode_message_poly(m: bytes) -> List[int]:
    if len(m) != 32:
        raise ValueError("CPAPKE message must be 32 bytes")
    half_q = Q // 2
    coeffs: List[int] = []
    for byte in m:
        for b in range(8):
            coeffs.append(((byte >> b) & 1) * half_q)
    return coeffs


def _matvec_mul_ntt(A_hat: List[List[List[int]]], r_hat: List[List[int]], k: int) -> List[List[int]]:
    out: List[List[int]] = []
    for i in range(k):
        acc = [0] * N
        for j in range(k):
            prod = poly_basemul_montgomery(A_hat[i][j], r_hat[j])
            acc = [(acc[c] + prod[c]) % Q for c in range(N)]
        out.append(acc)
    return out


def Enc(pk_bytes: bytes, m: bytes, coins: bytes, P: Dict) -> bytes:
    """CPAPKE.Enc aligned to kyber-py-main representation."""
    k = P["k"]
    du = P["du"]
    dv = P["dv"]
    eta1 = P["eta_1"]
    eta2 = P["eta_2"]

    t_hat, rho = unpack_pk(pk_bytes, k)
    m_poly = _encode_message_poly(m)

    # A^T: Parse(XOF(rho, i, j))
    A_hat_T: List[List[List[int]]] = [[None] * k for _ in range(k)]  # type: ignore
    for i in range(k):
        for j in range(k):
            A_hat_T[i][j] = parse(XOF(rho, i, j), n=N, q=Q)

    r_vec, e1_vec, nonce = sample_secret_and_noise(coins, k, eta1, eta2, nonce_start=0)
    e2_poly, _ = sample_cbd_poly(coins, nonce, eta2)

    r_hat = [to_ntt(poly) for poly in r_vec]

    # u = INTT(A^T_hat ⊙ r_hat) + e1
    u_hat = _matvec_mul_ntt(A_hat_T, r_hat, k)
    u_vec: List[List[int]] = []
    for i in range(k):
        u_i = from_ntt(u_hat[i])
        u_i = [(u_i[c] + e1_vec[i][c]) % Q for c in range(N)]
        u_vec.append(poly_reduce(u_i))

    # v = INTT(sum_j t_hat[j] ⊙ r_hat[j]) + e2 + m
    acc = [0] * N
    for j in range(k):
        prod = poly_basemul_montgomery(t_hat[j], r_hat[j])
        acc = [(acc[c] + prod[c]) % Q for c in range(N)]
    v = from_ntt(acc)
    v = [(v[c] + e2_poly[c] + m_poly[c]) % Q for c in range(N)]
    v = poly_reduce(v)

    c1 = pack_polyvec(u_vec, d=du, q=Q)
    c2 = pack_poly(v, d=dv, q=Q)
    return c1 + c2
