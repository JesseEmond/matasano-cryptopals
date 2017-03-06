from frequency import english_test


def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


def xor_single_char_key(msg, key):
    return xor_bytes(msg, bytes([key] * len(msg)))


def xor_repeating_key(msg, key):
    repeats, leftover = divmod(len(msg), len(key))
    return xor_bytes(msg, bytes(key * repeats + key[:leftover]))

def break_xor_char_key(ciphertext, quality_test=english_test):
    possible_keys = range(256)
    best_key = max(possible_keys,
                   key=lambda k:
                   quality_test(xor_single_char_key(ciphertext, k)))
    return best_key
