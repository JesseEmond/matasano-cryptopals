def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


def xor_single_char_key(msg, key):
    return xor_bytes(msg, bytes([key] * len(msg)))


def xor_repeating_key(msg, key):
    repeats = len(msg) // len(key)
    leftover = len(msg) % len(key)
    return xor_bytes(msg, bytes(key * repeats + key[:leftover]))
