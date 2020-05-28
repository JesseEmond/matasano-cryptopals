from .frequency import english_test
from .distance import hamming


def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


def xor_single_char_key(msg, key):
    return xor_bytes(msg, bytes([key] * len(msg)))


def xor_repeating_key(msg, key):
    repeats, leftover = divmod(len(msg), len(key))
    return xor_bytes(msg, bytes(key * repeats + key[:leftover]))


def break_xor_char_key(ciphertext, quality_test=english_test):
    return rank_xor_char_keys(ciphertext, quality_test)[0]


def rank_xor_char_keys(ciphertext, quality_test=english_test):
    possible_keys = range(256)
    decryptions = [(key, xor_single_char_key(ciphertext, key))
                   for key in possible_keys]
    # sort with a tuple to get deterministic results on quality equality
    best_decryptions = sorted(decryptions,
                              key=lambda key_decryption:
                              (quality_test(key_decryption[1]),
                               key_decryption[1]),
                              reverse=True)
    keys = [key for key, _ in best_decryptions]
    return keys


def break_xor_repeating_key(ciphertext, key_length,
                            quality_test=english_test):
    keys = rank_xor_repeating_keys(ciphertext, key_length, quality_test)
    key = [key_ranks[0] for key_ranks in keys]
    return bytes(key)


def rank_xor_repeating_keys(ciphertext, key_length, quality_test=english_test):
    blocks = [ciphertext[i * key_length:(i+1) * key_length]
              for i in range(len(ciphertext) // key_length)]
    nth_bytes = zip(*blocks)
    keys = [rank_xor_char_keys(bytes_, quality_test)
            for bytes_ in nth_bytes]
    return keys


def guess_key_lengths(cipher, min_length=2, max_length=40,
                      distance_fn=hamming):
    def score(cipher, size):
        distances = [distance_fn(cipher[i * size:(i+1) * size],
                                 cipher[(i+1) * size:(i+2) * size])
                     for i in range(len(cipher) // size - 2)]
        return sum(distances) / len(distances) / size

    return sorted(range(min_length, max_length+1),
                  key=lambda size: score(cipher, size))
