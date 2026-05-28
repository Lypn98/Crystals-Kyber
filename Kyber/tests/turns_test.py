import os
import sys
import argparse
from typing import Dict, Tuple

# このファイルが Kyber/tests/ にある前提で、2階層上(MyKyberTest)を import パスに追加
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)

from Kyber.parameters import Kyber512Parameters, Kyber768Parameters, Kyber1024Parameters
from Kyber.kem.KeyGen import KeyGen
from Kyber.kem.Enc import Enc
from Kyber.kem.Dec import Dec


def get_params(name: str) -> Dict:
    name = name.lower()
    if name in ("512", "kyber512"):
        return Kyber512Parameters
    if name in ("768", "kyber768"):
        return Kyber768Parameters
    if name in ("1024", "kyber1024"):
        return Kyber1024Parameters
    raise ValueError(f"Unknown parameter set: {name} (use 512/768/1024)")


def trial_once(P: Dict) -> Tuple[bool, bytes, bytes]:
    """
    1回分の試行：
      KeyGen → Enc → Dec
    戻り値: (success, m, m_dec)
    """
    pk, sk = KeyGen(P)

    # ランダムメッセージ（CPAPKE/KEMの前提：32バイト）
    m = os.urandom(32)

    # ランダム coins（Enc の乱数；Kyberでは 32 bytes 想定）
    coins = os.urandom(32)

    ct = Enc(pk, m, coins, P)
    m_dec = Dec(ct, sk, P)
    return (m_dec == m), m, m_dec


def run_trials(P: Dict, n: int, stop_on_fail: bool = False) -> int:
    """
    n回試行して失敗数を返す。
    """
    fails = 0
    for i in range(1, n + 1):
        ok, m, m_dec = trial_once(P)
        if not ok:
            fails += 1
            print(f"[FAIL] trial={i}")
            print(f"  m     : {m.hex()}")
            print(f"  m_dec : {m_dec.hex()}")
            if stop_on_fail:
                break

        # 進捗表示（必要なら調整）
        if i % max(1, (n // 10)) == 0 or i == n:
            print(f"[progress] {i}/{n} trials, fails={fails}")

    return fails


def main() -> None:
    parser = argparse.ArgumentParser(description="Kyber CPAPKE message roundtrip & decryption failure estimation")
    parser.add_argument("--param", default="512", help="parameter set: 512/768/1024 (default: 512)")
    parser.add_argument("--trials", type=int, default=1000, help="number of trials (default: 1000)")
    parser.add_argument("--stop-on-fail", action="store_true", help="stop at first failure (debug)")
    args = parser.parse_args()

    P = get_params(args.param)

    print("=== Settings ===")
    print("param :", args.param)
    print("trials:", args.trials)

    fails = run_trials(P, args.trials, stop_on_fail=args.stop_on_fail)
    p_hat = fails / args.trials

    print("\n=== Result ===")
    print(f"fails: {fails}/{args.trials}")
    print(f"estimated failure probability: {p_hat:.6g}")


if __name__ == "__main__":
    main()
