from Kyber.parameters import parameter_sets
from Kyber.kem import kem_keypair, kem_encaps, kem_decaps


def test_kem_roundtrip_kyber512():
    P = parameter_sets["Kyber512"]
    pk, sk = kem_keypair(P)
    ct, ss1 = kem_encaps(pk, P)
    ss2 = kem_decaps(ct, sk, P)
    assert ss1 == ss2


def test_kem_roundtrip_all_parameter_sets():
    # Quick smoke test across all sets
    for name, P in parameter_sets.items():
        pk, sk = kem_keypair(P)
        ct, ss1 = kem_encaps(pk, P)
        ss2 = kem_decaps(ct, sk, P)
        assert ss1 == ss2, f"KEM roundtrip failed for {name}"
