from frequency import english_test
from distance import hamming


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


def break_xor_repeating_key(ciphertext, key_length,
                            quality_test=english_test):
    blocks = [ciphertext[i * key_length:(i+1) * key_length]
              for i in range(len(ciphertext) // key_length)]
    nth_bytes = zip(*blocks)
    key = bytes([break_xor_char_key(bytes_, quality_test)
                 for bytes_ in nth_bytes])

    return key


def guess_key_lengths(cipher, min_length=2, max_length=40,
                      distance_fn=hamming):
    def score(cipher, size):
        distances = [distance_fn(cipher[i * size:(i+1) * size],
                                 cipher[(i+1) * size:(i+2) * size])
                     for i in range(len(cipher) // size - 2)]
        return sum(distances) / len(distances) / size

    return sorted(range(min_length, max_length+1),
                  key=lambda size: score(cipher, size))
