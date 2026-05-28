import random,os,sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Kyber.utils.Encode import (
    poly_tobytes, poly_frombytes,
    polyvec_tobytes, polyvec_frombytes,
    pack_pk, unpack_pk,
    pack_sk, unpack_sk,
)
from Kyber.parameters import Kyber512Parameters

Q = Kyber512Parameters["q"]
N = Kyber512Parameters["n"]
K = Kyber512Parameters["k"]

def _rand_poly(rng: random.Random):
    # poly_tobytes 系は係数が [0, q) を仮定することが多いのでその範囲で生成
    return [rng.randrange(Q) for _ in range(N)]

def _rand_polyvec(rng: random.Random):
    return [_rand_poly(rng) for _ in range(K)]

def test_poly_bytes_roundtrip():
    rng = random.Random(1)
    for _ in range(200):
        a = _rand_poly(rng)
        b = poly_frombytes(poly_tobytes(a))
        assert [x % Q for x in b] == [x % Q for x in a]

def test_polyvec_bytes_roundtrip():
    rng = random.Random(2)
    for _ in range(100):
        v = _rand_polyvec(rng)
        b = polyvec_frombytes(polyvec_tobytes(v), K)
        assert [[x % Q for x in poly] for poly in b] == [[x % Q for x in poly] for poly in v]

def test_pack_unpack_pk_roundtrip():
    rng = random.Random(3)
    for _ in range(100):
        t_vec = _rand_polyvec(rng)
        rho = bytes(rng.randrange(256) for _ in range(32))
        pk = pack_pk(t_vec, rho, K)
        t2, rho2 = unpack_pk(pk, K)
        assert rho2 == rho
        assert [[x % Q for x in poly] for poly in t2] == [[x % Q for x in poly] for poly in t_vec]

def test_pack_unpack_sk_roundtrip():
    rng = random.Random(4)
    for _ in range(100):
        s_vec = _rand_polyvec(rng)
        sk = pack_sk(s_vec, K)
        s2 = unpack_sk(sk, K)
        assert [[x % Q for x in poly] for poly in s2] == [[x % Q for x in poly] for poly in s_vec]
