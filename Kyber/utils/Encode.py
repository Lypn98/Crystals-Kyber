from typing import List, Tuple
# Kyber/utils/encode.py
# -----------------------------------------------
# Kyber poly/polyvec Encode/Decode（非圧縮版）
# 公式 ref/poly.c と完全互換の12bit×2→3B 直列化
# -----------------------------------------------

from typing import List

Q = 3329
N = 256

def _to_pos_repr(u: int) -> int:
    """直列化前に 0..Q-1 の正準代表へ（公式poly_tobytesの符号補正と同等）。
    """
    # 公式の書き方に合わせたい場合は下記でも良い（符号ビットを模す）
    u += ((u >> 15) & Q)
    return u

# -------------------------------
# poly（256係数）の非圧縮直列化
# -------------------------------
def poly_tobytes(a: List[int]) -> bytes:
    #assertは真でなければエラー
    assert len(a) == N, f"poly_tobytes: length must be {N}"
    #bytearrayは可変バイト列
    out = bytearray()
    for i in range(0, N, 2):
        t0 = _to_pos_repr(a[i])
        t1 = _to_pos_repr(a[i+1])
        # 12bitずつ詰める（公式と同配置）
        #b0はt0の下位8bit
        b0 = (t0 >> 0) & 0xFF
        #b1はt0の上位4bit + t1の下位4bit
        b1 = ((t0 >> 8) & 0x0F) | ((t1 & 0x0F) << 4)
        #b2はt1の上位8bit
        b2 = (t1 >> 4) & 0xFF
        out.extend([b0, b1, b2])
    return bytes(out)

#384バイト → 256係数の多項式
def poly_frombytes(buf: bytes) -> List[int]:
    exp_len = (N // 2) * 3
    assert len(buf) == exp_len, f"poly_frombytes: length must be {exp_len} bytes"
    a = [0] * N
    idx = 0
    for i in range(0, N, 2):
        b0 = buf[idx]
        b1 = buf[idx+1]
        b2 = buf[idx+2]
        idx += 3
        # 12bit復元（公式と同式）
        t0 = ((b0) | ((b1 & 0x0F) << 8)) & 0xFFF
        t1 = (((b1 >> 4) & 0x0F) | (b2 << 4)) & 0xFFF
        a[i]   = t0
        a[i+1] = t1
    return a

# -------------------------------
# polyvec（長さk）の非圧縮直列化
# k本の多項式（List[List[int]]）→ k×384バイト
# -------------------------------
def polyvec_tobytes(vec: List[List[int]]) -> bytes:
    out = bytearray()
    for p in vec:
        out.extend(poly_tobytes(p))
    return bytes(out)

#k×384バイト → k本の多項式
def polyvec_frombytes(buf: bytes, k: int) -> List[List[int]]:
    one_len = (N // 2) * 3
    assert len(buf) == one_len * k, f"polyvec_frombytes: length must be {one_len*k}"
    vec = []
    off = 0
    for _ in range(k):
        vec.append(poly_frombytes(buf[off:off+one_len]))
        off += one_len
    return vec

# -------------------------------
# 公開鍵/秘密鍵（CPA-PKE）パック
#   pk = Encode_polyvec(t) || rho(32B)
#   sk = Encode_polyvec(s)
# -------------------------------
def pack_pk(t_vec: List[List[int]], rho: bytes,k:int) -> bytes:
    assert len(rho) == 32, "rho must be 32 bytes"
    return polyvec_tobytes(t_vec) + rho


#公開鍵バイト列 → (t_vec, rho)
def unpack_pk(pk_bytes: bytes, k: int) -> Tuple[List[List[int]], bytes]:
    one_len = (N // 2) * 3
    t_len = one_len * k
    assert len(pk_bytes) >= t_len + 32, "pk length is too short"
    t_vec = polyvec_frombytes(pk_bytes[:t_len], k)
    rho   = pk_bytes[t_len:t_len+32]
    return t_vec, rho

def pack_sk(s_vec: List[List[int]],k:int) -> bytes:
    return polyvec_tobytes(s_vec)



def unpack_sk(sk_bytes: bytes, k: int) -> List[List[int]]:
    return polyvec_frombytes(sk_bytes, k)


if __name__ == "__main__":
    import os, random

    def rand_poly():
        # 0..Q-1 のランダム係数
        return [random.randrange(Q) for _ in range(N)]

    # t_vec: k本
    for k in (2,3,4):
        t_vec = [rand_poly() for _ in range(k)]
        rho = os.urandom(32)
        pk = pack_pk(t_vec, rho, k)
        t2, rho2 = unpack_pk(pk, k)
        assert rho2 == rho
        assert t2 == t_vec
        print(f"[PK OK] k={k} pk_len={len(pk)}")

        # sk（CPAPKE版）
        s_vec = [[random.randrange(Q) for _ in range(N)] for _ in range(k)]
        sk = pack_sk(s_vec, k)
        s2 = unpack_sk(sk, k)
        assert s2 == s_vec
        print(f"[SK OK] k={k} sk_len={len(sk)}")
