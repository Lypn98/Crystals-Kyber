import os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)
from Kyber.parameters import Kyber512Parameters
from Kyber.kem.KeyGen import KeyGen
from Kyber.kem.Enc import Enc
from Kyber.kem.Dec import Dec


def messageTest():
    """
    CPAPKE: KeyGen → Enc → Dec で
    メッセージ m が完全に一致するかを確認するテスト
    """
    P = Kyber512Parameters

    # 鍵生成
    pk, sk = KeyGen(P)

    # 32バイトメッセージ（CPAPKE仕様）
    m = bytes(range(32))  # 00 01 02 ... 1f

    # 暗号化用乱数（固定して再現性を持たせる）
    coins = bytes([42] * 32)

    # 暗号化
    ct = Enc(pk, m, coins, P)
    print(m)

    # 復号
    m_dec = Dec(ct, sk, P)
    print(m_dec)

    # 検証
    assert m_dec == m, (
        f"message mismatch!\n"
        f"original: {m.hex()}\n"
        f"decoded : {m_dec.hex()}"
    )

    print("[OK] message roundtrip succeeded")
    return True


if __name__ == "__main__":
    messageTest()
