# Following the pseudocode on https://en.wikipedia.org/wiki/SHA-1
from . import bitops
from . import merkle_damgard


class Sha1(merkle_damgard.Hash):
    def __init__(self, hs=None, msg_len=0):
        hs = hs or (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
        super(Sha1, self).__init__(hs, msg_len)

    def process_chunk(self, chunk, state):
        assert len(chunk) == 64
        w = [0] * 80
        for i in range(16):
            w[i] = int.from_bytes(chunk[i*4:i*4 + 4], "big")
        for i in range(16, 80):
            w[i] = bitops.left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)

        a, b, c, d, e = state

        for i in range(80):
            if i < 20:
                f = d ^ (b & (c ^ d))  # Alternative 1 to avoid bitwise not
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            new_a = (bitops.left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
            new_c = bitops.left_rotate(b, 30)
            a, b, c, d, e = new_a, a, new_c, c, d

        chunk_hs = (a, b, c, d, e)
        return tuple((h_i + chunk_h_i) & 0xFFFFFFFF
                     for h_i, chunk_h_i in zip(state, chunk_hs))


def sha1(message):
    return Sha1().update(message).digest()
assert(sha1(b"The quick brown fox jumps over the lazy dog") ==
        bytes.fromhex("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"))
assert(sha1(b"The quick brown fox jumps over the lazy cog") ==
        bytes.fromhex("de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"))
assert(sha1(b"") ==
        bytes.fromhex("da39a3ee5e6b4b0d3255bfef95601890afd80709"))


def __test_length_extension():
    new_digest, to_append = Sha1.length_extension_attack(sha1(b"hello"), len(b"hello"), b"world")
    padding = Sha1.length_padding(msg_len=len(b"hello"))
    assert to_append == padding + b"world"
    # Test that we're able to bootstrap from an existing digest properly.
    assert new_digest == sha1(b"hello" + padding + b"world")

__test_length_extension()