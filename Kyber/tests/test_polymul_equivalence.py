import random,os,sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Kyber.utils.NTT import polymul_ntt, Q, N

def polymul_naive(a, b):
    # R_q = Z_q[x]/(x^N + 1) のナイーブ積
    res = [0] * N
    for i in range(N):
        ai = a[i] % Q
        for j in range(N):
            t = ai * (b[j] % Q)
            k = i + j
            if k < N:
                res[k] += t
            else:
                # x^N == -1
                res[k - N] -= t
    return [x % Q for x in res]

def test_polymul_ntt_matches_naive():
    """
    NTT を使う積と、ナイーブ積が一致するか（mod q）。
    NTT が正しいなら必ず一致する。
    """
    rng = random.Random(20240101)
    for _ in range(100):
        a = [rng.randrange(Q) for _ in range(N)]
        b = [rng.randrange(Q) for _ in range(N)]
        got = [x % Q for x in polymul_ntt(a, b)]
        exp = polymul_naive(a, b)
        assert got == exp
