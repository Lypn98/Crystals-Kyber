import hashlib

# Kyber仕様: G(input) を SHA3-512 で実装。
def G(input_bytes: bytes) -> bytes:
    return hashlib.sha3_512(input_bytes).digest()


def H(input_bytes: bytes) -> bytes:
    """Kyber specification: H(x) = SHA3-256(x)."""
    return hashlib.sha3_256(input_bytes).digest()


def KDF(input_bytes: bytes, outlen: int = 32) -> bytes:
    """Kyber specification: KDF(x) = SHAKE-256(x, outlen)."""
    return hashlib.shake_256(input_bytes).digest(outlen)

class XOF:
    """
    Python標準hashlibは read() を持たないため、digest(len)の接頭辞不変性を利用して、必要な分だけ出力を生成する。
    """
    #コンストラクタを定義
    def __init__(self, rho: bytes, i: int, j: int):
        #i,j は 0〜255 の範囲
        assert 0 <= i < 256 and 0 <= j < 256

        self._msg = rho + bytes([i]) + bytes([j]) 
        #現在の読み出し位置（何バイト既に供給したか）を保持。後の read(n) で「どこからどこまで」を切り出すための内部状態。
        self._pos = 0
        #最新の出力バッファ。digest(needed) の結果を保持し、部分切り出しに使う。
        self._buf = b''

    def read(self, n: int) -> bytes:
        """
        次の n バイトを返す。内部で digest(prefix_len) を使って出力長を延長する。
        """
        # 必要な出力長を計算
        needed = self._pos + n
        # SHAKEの性質: より長いdigestは短いdigestの接頭辞を保つ。
        self._buf = hashlib.shake_128(self._msg).digest(needed)
        #戻り値を切り出し、位置を更新
        out = self._buf[self._pos:self._pos + n]
        self._pos += n
        return out


def PRF(sigma: bytes, nonce: int, outlen: int) -> bytes:
    """
    PRF(σ, nonce): SHAKE-256(σ || [nonce]) から outlen バイトを取得。
    """
    assert 0 <= nonce < 256
    assert len(sigma) == 32 # Kyber仕様
    return hashlib.shake_256(sigma + bytes([nonce])).digest(outlen)

