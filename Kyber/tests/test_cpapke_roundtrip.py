import os,sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Kyber.parameters import Kyber512Parameters
from Kyber.kem.KeyGen import KeyGen
from Kyber.kem.Enc import Enc
from Kyber.kem.Dec import Dec

def test_cpapke_roundtrip_fixed_randomness(monkeypatch):
    """
    KeyGen → Enc → Dec で m が戻るか（固定乱数で決定的に）。
    ここが通れば “暗号として使える” ことの最重要証拠になる。
    """
    P = Kyber512Parameters

    # KeyGen 内部の os.urandom(32) を固定
    fixed_d = b"D" * 32
    def fake_urandom(n: int) -> bytes:
        assert n == 32
        return fixed_d
    monkeypatch.setattr(os, "urandom", fake_urandom)

    pk, sk = KeyGen(P)

    # Enc は r を引数でもらえるので固定値を投入
    r = b"R" * 32
    m = bytes(range(32))  # 32-byte message
    ct = Enc(pk, m, r, P)
    m2 = Dec(ct, sk, P)

    # 実装が list[int] を返す場合に備えて正規化
    if isinstance(m2, list):
        m2 = bytes(m2)

    assert m2 == m
