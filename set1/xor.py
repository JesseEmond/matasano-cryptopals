def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])
