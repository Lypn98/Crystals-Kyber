from __future__ import annotations

import hmac
import os
from typing import Dict, Tuple

from Kyber.kem.KeyGen import KeyGen as indcpa_keygen
from Kyber.kem.Enc import Enc as indcpa_enc
from Kyber.kem.Dec import Dec as indcpa_dec
from Kyber.utils.Hash import G, H, KDF
from Kyber.utils.NTT import N


def kem_keypair(P: Dict) -> Tuple[bytes, bytes]:
    """Kyber CCA-secure KEM key generation.

    This is the standard Kyber KEM transform (Fujisaki-Okamoto style):
      sk = sk_indcpa || pk || H(pk) || z
    where z is a random 32-byte fallback key.
    """

    pk, sk_indcpa = indcpa_keygen(P)
    pk_hash = H(pk)
    z = os.urandom(32)
    sk = sk_indcpa + pk + pk_hash + z
    return pk, sk


def kem_encaps(pk: bytes, P: Dict) -> Tuple[bytes, bytes]:
    """Kyber KEM encapsulation.

    Returns (ct, ss) where:
      (K, r) = G(m || H(pk))
      ct = INDCPA.Enc(pk, m, r)
      ss = KDF(K || H(ct))
    """

    # Kyber: m = H(random32)
    m = H(os.urandom(32))
    pk_hash = H(pk)
    kr = G(m + pk_hash)
    K, r = kr[:32], kr[32:]

    ct = indcpa_enc(pk, m, r, P)
    ss = KDF(K + H(ct), outlen=P.get("KYBER_SSBYTES", 32))
    return ct, ss


def kem_decaps(ct: bytes, sk: bytes, P: Dict) -> bytes:
    """Kyber KEM decapsulation.

    If ciphertext validation fails, uses z (stored in sk) instead of K.
    """

    k = P["k"]
    # This codebase packs INDCPA keys using poly_tobytes (384 bytes/poly),
    # not the compressed sizes in some parameter tables.
    poly_bytes = (N // 2) * 3
    sk_indcpa_len = poly_bytes * k
    pk_len = poly_bytes * k + 32
    sym = P.get("KYBER_SYMBYTES", 32)

    if len(sk) < sk_indcpa_len + pk_len + 2 * sym:
        raise ValueError("Invalid KEM secret key length")

    sk_indcpa = sk[:sk_indcpa_len]
    pk = sk[sk_indcpa_len:sk_indcpa_len + pk_len]
    pk_hash = sk[sk_indcpa_len + pk_len:sk_indcpa_len + pk_len + sym]
    z = sk[sk_indcpa_len + pk_len + sym:sk_indcpa_len + pk_len + 2 * sym]

    # m' = INDCPA.Dec(ct, sk_indcpa)
    m_prime = indcpa_dec(ct, sk_indcpa, P)

    kr = G(m_prime + pk_hash)
    K, r = kr[:32], kr[32:]

    ct_check = indcpa_enc(pk, m_prime, r, P)

    # Constant-time ciphertext comparison
    if not hmac.compare_digest(ct, ct_check):
        K = z

    ss = KDF(K + H(ct), outlen=P.get("KYBER_SSBYTES", 32))
    return ss
