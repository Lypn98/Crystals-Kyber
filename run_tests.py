# run_tests.py
from __future__ import annotations

import os
import sys
import subprocess
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent
    kyber_dir = root / "Kyber"
    tests_dir = kyber_dir / "tests"

    if not kyber_dir.exists() or not tests_dir.exists():
        print("[ERROR] run_tests.py はプロジェクトルートに置いてください。")
        print("        例: (root)/run_tests.py と (root)/Kyber/tests が存在する状態")
        return 2

    # pytest が見つからなければエラー
    try:
        import pytest  # noqa: F401
    except Exception:
        print("[ERROR] pytest がインストールされていません。")
        print("        pip install -U pytest")
        return 2

    # import 解決のためにプロジェクトルートを PYTHONPATH に入れる
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")

    print("=== Environment ===")
    print("Python:", sys.version.replace("\n", " "))
    print("Root  :", root)
    print("PYTHONPATH includes root:", root)

    # 1) まずは pytest をフルで回す
    print("\n=== Running pytest ===")
    cmd = [sys.executable, "-m", "pytest", "-q", str(tests_dir), "-s"]
    print("Command:", " ".join(cmd))
    r = subprocess.run(cmd, cwd=str(root), env=env)
    if r.returncode != 0:
        print("\n[FAIL] pytest failed.")
        return r.returncode

    # 2) 追加の簡易スモーク（任意だが、バグの早期検出に有効）
    print("\n=== Extra smoke checks ===")
    try:
        from Kyber.utils.NTT import Q, to_ntt, from_ntt, polymul_ntt, polymul_naive
        import random

        rng = random.Random(0)
        for _ in range(30):
            a = [rng.randrange(Q) for _ in range(256)]
            b = [rng.randrange(Q) for _ in range(256)]
            # NTT roundtrip
            a2 = from_ntt(to_ntt(a))
            if [(x - y) % Q for x, y in zip(a2, a)] != [0] * 256:
                raise AssertionError("from_ntt(to_ntt(a)) != a mod q")
            # polymul equivalence
            c1 = polymul_ntt(a, b)
            c2 = polymul_naive(a, b)
            if [(x - y) % Q for x, y in zip(c1, c2)] != [0] * 256:
                raise AssertionError("polymul_ntt != polymul_naive mod q")

        print("[OK] smoke checks passed.")
    except Exception as e:
        print("[FAIL] smoke checks failed:", repr(e))
        return 1

    print("\n[OK] All tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
