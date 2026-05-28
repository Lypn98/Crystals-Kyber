
Kyber1024Parameters = {
    "n": 256,
    "k": 4,
    "q": 3329,
    "eta_1": 2,
    "eta_2": 2,
    "du": 11,
    "dv": 5,

    "SEED_BYTES": 32,  # Kyber仕様固定
    "KYBER_SYMBYTES": 32,
    "KYBER_SSBYTES": 32,

    "KYBER_POLYBYTES": 384,
    "KYBER_POLYCOMPRESSEDBYTES": 160,
    "KYBER_POLYVECBYTES": (4 * 352),

    "KYBER_INDCPA_PUBLICKEYBYTES": (4 * 352) + 32,
    "KYBER_INDCPA_SECRETKEYBYTES": (4 * 352),
    "KYBER_INDCPA_BYTES": (4 * 352) + 160,

    # optional: ntt constants
    "QINV": 62209,
    "MONT": 1 << 16
}
