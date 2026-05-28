import random,os,sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Kyber.utils.NTT import ntt, inv_ntt, Q, N,from_ntt, to_ntt


def _rand_poly(rng: random.Random):
    return [rng.randrange(Q) for _ in range(N)]

def test_ntt_roundtrip_identity_mod_q():
    rng = random.Random(12345)
    for _ in range(200):
        a = _rand_poly(rng)
        a2 = from_ntt(to_ntt(a))
        assert [x % Q for x in a2] == [x % Q for x in a]