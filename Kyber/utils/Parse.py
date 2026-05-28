def parse(xof, n=256, q=3329):
    coeffs = []

    while len(coeffs) < n:
        # 3 バイト読み出す
        block = xof.read(3)
        b0, b1, b2 = block[0], block[1], block[2]

        # d1, d2 を求める
        d1 = b0 + 256 * (b1 & 0x0F)
        d2 = (b1 >> 4) + 16 * b2

        if d1 < q:
            coeffs.append(d1)
        if d2 < q and len(coeffs) < n:
            coeffs.append(d2)

    return coeffs

