from __future__ import annotations

import os
from typing import Dict, List, Tuple

from Kyber.utils.Hash import G, XOF
from Kyber.utils.Parse import parse
from Kyber.utils.CBD import sample_secret_and_noise
from Kyber.utils.NTT import Q, N, to_ntt, poly_basemul_montgomery, poly_reduce
from Kyber.utils.Encode import pack_pk, pack_sk


def _matvec_mul_ntt(A_hat: List[List[List[int]]], s_hat: List[List[int]], k: int) -> List[List[int]]:
    out: List[List[int]] = []
    for i in range(k):
        acc = [0] * N
        for j in range(k):
            prod = poly_basemul_montgomery(A_hat[i][j], s_hat[j])
            acc = [(acc[c] + prod[c]) % Q for c in range(N)]
        out.append(acc)
    return out


def KeyGen(P: Dict) -> Tuple[bytes, bytes]:
    """
    CPAPKE.KeyGen aligned to kyber-py-main:
      - sample s and e with eta1 (both)
      - store s_hat and t_hat (NTT domain) in sk/pk
      - pk = Encode(t_hat) || rho
      - sk = Encode(s_hat)
    """
    k = P["k"]
    eta1 = P["eta_1"]

    d = os.urandom(32)
    g = G(d)
    rho, sigma = g[:32], g[32:]

    # Build A_hat (NTT-domain polynomials from Parse)
    A_hat: List[List[List[int]]] = [[None] * k for _ in range(k)]  # type: ignore
    for i in range(k):
        for j in range(k):
            A_hat[i][j] = parse(XOF(rho, j, i), n=N, q=Q)

    # KeyGen uses eta1 for both s and e (important difference vs your previous code)
    s_vec, e_vec, _ = sample_secret_and_noise(sigma, k, eta1, eta1, nonce_start=0)

    s_hat = [to_ntt(poly) for poly in s_vec]
    e_hat = [to_ntt(poly) for poly in e_vec]

    t_hat = _matvec_mul_ntt(A_hat, s_hat, k)
    for i in range(k):
        t_hat[i] = [(t_hat[i][c] + e_hat[i][c]) % Q for c in range(N)]
        t_hat[i] = poly_reduce(t_hat[i])
        s_hat[i] = poly_reduce(s_hat[i])

    pk = pack_pk(t_hat, rho, k)
    sk = pack_sk(s_hat, k)
    return pk, sk
