Kyber512Parameters = {
    "n": 256,
    "k": 2,
    "q": 3329,
    "eta_1": 3,
    "eta_2": 2,
    "du": 10,
    "dv": 4,

    "SEED_BYTES": 32,  # Kyber仕様固定
    "KYBER_SYMBYTES": 32,
    "KYBER_SSBYTES": 32,

    "KYBER_POLYBYTES": 384,
    "KYBER_POLYCOMPRESSEDBYTES": 128,
    "KYBER_POLYVECBYTES": (2 * 320),

    "KYBER_INDCPA_PUBLICKEYBYTES": (2 * 320) + 32,
    "KYBER_INDCPA_SECRETKEYBYTES": (2 * 320),
    "KYBER_INDCPA_BYTES": (2 * 320) + 128,

    # optional: ntt constants
    "QINV": 62209,
    "MONT": 1 << 16
}
