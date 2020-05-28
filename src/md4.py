import bitops
import merkle_damgard

import struct


def f(x, y, z):
    return (x & y) | (bitops.bit_not(x) & z)


def g(x, y, z):
    return (x & y) | (x & z) | (y & z)


def h(x, y, z):
    return x ^ y ^ z


def round_1_op(a, b, c, d, k, s, x):
    """(a + F(b,c,d) + X[k]) <<< s"""
    sum_ = (a + f(b, c, d) + x[k]) & 0xFFFFFFFF
    return bitops.left_rotate(sum_, s)


def round_2_op(a, b, c, d, k, s, x):
    """(a + G(b,c,d) + X[k] + 5A827999) <<< s"""
    sum_ = (a + g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF
    return bitops.left_rotate(sum_, s)


def round_3_op(a, b, c, d, k, s, x):
    """(a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s"""
    sum_ = (a + h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF
    return bitops.left_rotate(sum_, s)


def round_1(x, a, b, c, d):
    """Do the following 16 operations:

    [ABCD  0  3]  [DABC  1  7]  [CDAB  2 11]  [BCDA  3 19]
    [ABCD  4  3]  [DABC  5  7]  [CDAB  6 11]  [BCDA  7 19]
    [ABCD  8  3]  [DABC  9  7]  [CDAB 10 11]  [BCDA 11 19]
    [ABCD 12  3]  [DABC 13  7]  [CDAB 14 11]  [BCDA 15 19]
    """
    for i in [0, 4, 8, 12]:
        a = round_1_op(a, b, c, d, i+0, 3, x)
        d = round_1_op(d, a, b, c, i+1, 7, x)
        c = round_1_op(c, d, a, b, i+2, 11, x)
        b = round_1_op(b, c, d, a, i+3, 19, x)
    return a, b, c, d


def round_2(x, a, b, c, d):
    """Do the following 16 operations:
    [ABCD  0  3]  [DABC  4  5]  [CDAB  8  9]  [BCDA 12 13]
    [ABCD  1  3]  [DABC  5  5]  [CDAB  9  9]  [BCDA 13 13]
    [ABCD  2  3]  [DABC  6  5]  [CDAB 10  9]  [BCDA 14 13]
    [ABCD  3  3]  [DABC  7  5]  [CDAB 11  9]  [BCDA 15 13]
    """
    for i in [0, 1, 2, 3]:
        a = round_2_op(a, b, c, d, i+0, 3, x)
        d = round_2_op(d, a, b, c, i+4, 5, x)
        c = round_2_op(c, d, a, b, i+8, 9, x)
        b = round_2_op(b, c, d, a, i+12, 13, x)
    return a, b, c, d


def round_3(x, a, b, c, d):
    """Do the following 16 operations:
    [ABCD  0  3]  [DABC  8  9]  [CDAB  4 11]  [BCDA 12 15]
    [ABCD  2  3]  [DABC 10  9]  [CDAB  6 11]  [BCDA 14 15]
    [ABCD  1  3]  [DABC  9  9]  [CDAB  5 11]  [BCDA 13 15]
    [ABCD  3  3]  [DABC 11  9]  [CDAB  7 11]  [BCDA 15 15]
    """
    for i in [0, 2, 1, 3]:
        a = round_3_op(a, b, c, d, i+0, 3, x)
        d = round_3_op(d, a, b, c, i+8, 9, x)
        c = round_3_op(c, d, a, b, i+4, 11, x)
        b = round_3_op(b, c, d, a, i+12, 15, x)
    return a, b, c, d


class Md4(merkle_damgard.Hash):

    ENDIANNESS = "little"

    def __init__(self, state=None, msg_len=0):
        state = state or (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
        super(Md4, self).__init__(state, msg_len)

    def process_chunk(self, chunk, state):
        assert len(chunk) == 64
        x = [int.from_bytes(chunk[i:i + 4], self.ENDIANNESS)
             for i in range(0, 64, 4)]
        orig_state = tuple(state)
        state = round_1(x, *state)
        state = round_2(x, *state)
        state = round_3(x, *state)
        return tuple((orig_i + state_i) & 0xFFFFFFFF
                     for orig_i, state_i in zip(orig_state, state))



def md4(message):
    return Md4().update(message).digest()
assert md4(b"") == bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0")
assert md4(b"a") == bytes.fromhex("bde52cb31de33e46245e05fbdbd6fb24")
assert(md4(b"The quick brown fox jumps over the lazy dog") ==
       bytes.fromhex("1bee69a46ba811185c194762abaeae90"))
assert(md4(b"The quick brown fox jumps over the lazy cog") ==
       bytes.fromhex("b86e130ce7028da59e672d56ad0113df"))