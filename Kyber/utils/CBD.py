from typing import List, Tuple

from Kyber.utils.Hash import PRF

KYBER_N = 256
Q = 3329
#_cbd_eta_from_bytes() でそのバイト列を CBD_ηに従って256係数の整数列（範囲 [-η, η]）へ変換する。
def _cbd_eta_from_bytes(buf: bytes, eta: int) -> List[int]:
    """
    CBD_η：バイト列から 256 係数の雑音多項式（各係数 ∈ [-η, η]）を生成。
    入力長は 64*η バイト（η=2→128B, η=3→192B）。
    """
    if eta == 2:
        # 4バイト（=32ビット）を1ブロックとして処理 → 各ブロックから8係数を取り出す → 32ブロック × 8係数 = 256係数。
        #入力が64*2=128バイトであることを確認
        if len(buf) != 64 * eta:
            raise ValueError("CBD(eta=2) requires 128 bytes")
        coeffs = [0] * KYBER_N
        for i in range(KYBER_N // 8):  # 32 回繰り返し
            t = int.from_bytes(buf[4*i:4*i+4], 'little')  # 32-bit
            #右から０，１，２ビット目としている。
            #0x55555555は2進数で010101010101...となり、t & 0x55555555 で 偶数位置ビット（b0, b2, …）を抽出。
            #(t >> 1) & 0x55555555 で 奇数位置ビット（b1, b3, …）を抽出。
            #t>>1 は t を1ビット右シフトする操作。
            d = (t & 0x55555555) + ((t >> 1) & 0x55555555)  # 2-bit sums（ref準拠）
            # 8 係数を取り出し
            for j in range(8):
                #a = (d >> (4*j + 0)) & 0x3 → 前半2ビット, b = (d >> (4*j + 2)) & 0x3 → 後半2ビット
                a = (d >> (4*j + 0)) & 0x3
                b = (d >> (4*j + 2)) & 0x3
                coeffs[8*i + j] = a - b
        return [c % Q for c in coeffs]

    elif eta == 3:
        # 192 bytes -> 64 blocks of 3 bytes; each 24-bit word yields 4 coeffs = 256.
        if len(buf) != 64 * eta:
            raise ValueError("CBD(eta=3) requires 192 bytes")
        coeffs = [0] * KYBER_N
        for i in range(KYBER_N // 4):  # 64 iterations
            t = buf[3*i] | (buf[3*i + 1] << 8) | (buf[3*i + 2] << 16)  # 24-bit
            #これはビット列tを３つのグループに分ける操作。
            d = 0
            #元のビット列でt のうち「0,3,6,9,12,15,18,21 番ビット」
            d += (t >> 0) & 0x249249
            #元のビット列でt のうち「1,4,7,10,13,16,19,22 番ビット」
            d += (t >> 1) & 0x249249
            #元のビット列でt のうち「2,5,8,11,14,17,20,23 番ビット」
            d += (t >> 2) & 0x249249
            
            # 4係数を取り出し
            a0 = (d >>  0) & 0x7; b0 = (d >>  3) & 0x7
            a1 = (d >>  6) & 0x7; b1 = (d >>  9) & 0x7
            a2 = (d >> 12) & 0x7; b2 = (d >> 15) & 0x7
            a3 = (d >> 18) & 0x7; b3 = (d >> 21) & 0x7
            idx = 4 * i
            coeffs[idx + 0] = a0 - b0
            coeffs[idx + 1] = a1 - b1
            coeffs[idx + 2] = a2 - b2
            coeffs[idx + 3] = a3 - b3
        return [c % Q for c in coeffs]

    else:
        raise ValueError("Supported eta are 2 or 3 for Kyber")

def sample_cbd_poly(sigma: bytes, nonce: int, eta: int) -> Tuple[List[int], int]:
    """
    PRF(σ, nonce) から 64*η バイトを取り、CBD_η で 256係数の多項式を返す。
    戻り値は (poly, 次のnonce)。
    """
    buf = PRF(sigma, nonce, outlen=64*eta)  # 仕様：PRFにSHAKE-256を用いる。
    poly = _cbd_eta_from_bytes(buf, eta)
    #同じ sigma でも nonce が違えば PRFの出力が変わる → 異なるノイズ多項式が得られる。だからnonce+1
    return poly, (nonce + 1) % 256
#sample_secret_and_noise() で KeyGenに必要な s と e の k本を、nonce を増やしながら連続生成する。
#Tupleは複数の戻り値を返す。
def sample_secret_and_noise(sigma: bytes, k: int, eta1: int, eta2: int,
                            nonce_start: int = 0) -> Tuple[List[List[int]], List[List[int]], int]:
    """
    KeyGenで必要な s[0..k-1], e[0..k-1] を生成。
    s[i] := CBD_{η1}(PRF(σ,N)); N=N+1
    e[i] := CBD_{η2}(PRF(σ,N)); N=N+1（仕様の流れに準拠）
    """
    s_vec, e_vec = [], []
    N = nonce_start
    for _ in range(k):
        s_poly, N = sample_cbd_poly(sigma, N, eta1)
        s_vec.append(s_poly)
    for _ in range(k):
        e_poly, N = sample_cbd_poly(sigma, N, eta2)
        e_vec.append(e_poly)
    return s_vec, e_vec, N
