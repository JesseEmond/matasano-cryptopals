# Following the pseudocode on https://en.wikipedia.org/wiki/SHA-1


def left_rotate(x, n):
    """Left rotate a 32-bit integer x by n bits."""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
assert left_rotate(0b1000, 1) == 0b10000


def process_chunk(chunk, h0, h1, h2, h3, h4):
    assert len(chunk) == 64
    w = [0] * 80
    for i in range(16):
        w[i] = int.from_bytes(chunk[i*4:i*4 + 4], "big")
    for i in range(16, 80):
        w[i] = left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)

    a, b, c, d, e = h0, h1, h2, h3, h4

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
        new_a = (left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        new_c = left_rotate(b, 30)
        a, b, c, d, e = new_a, a, new_c, c, d

    hs = (h0, h1, h2, h3, h4)
    chunk_hs = (a, b, c, d, e)
    return tuple((h_i + chunk_h_i) & 0xFFFFFFFF
                 for h_i, chunk_h_i in zip(hs, chunk_hs))


def get_glue(msg_len):
    """Produces the padding that should be appended to the message."""
    glue = bytearray()
    # Append bit '1' (0x80 because message is multiple of 8-bits)
    glue.append(0x80)

    # Want final_msg_len % 64 = 56.
    new_len = msg_len + 1  # including the '1' bit added
    missing_len = (56 - (new_len % 64)) % 64
    glue.extend(b"\x00" * missing_len)

    # Append the original length, as 64-bit big-endian.
    msg_len_bits = msg_len * 8
    glue.extend(msg_len_bits.to_bytes(8, "big"))

    return bytes(glue)


class Sha1():
    def __init__(self, hs=None):
        self._h = hs or (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
        self._unprocessed = bytearray()
        self._msg_len = 0

    def update(self, data):
        self._msg_len += len(data)
        self._unprocessed.extend(data)
        self._process_unprocessed()
        return self

    def digest(self):
        glue = get_glue(self._msg_len)
        self._unprocessed.extend(glue)
        assert len(self._unprocessed) % 64 == 0
        self._process_unprocessed()
        assert len(self._unprocessed) == 0
        return b"".join(h.to_bytes(4, "big") for h in self._h)

    def _process_unprocessed(self):
        while len(self._unprocessed) >= 64:  # While we have chunks of 512-bits
            self._h = process_chunk(self._unprocessed[:64], *self._h)
            self._unprocessed = self._unprocessed[64:]

    def bootstrap(self, digest, msg_len):
        """Bootstrap the state from an existing digest, for length-extension attacks."""
        return self  # TODO


def sha1(message):
    return Sha1().update(message).digest()


assert(sha1(b"The quick brown fox jumps over the lazy dog") ==
        bytes.fromhex("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"))
assert(sha1(b"The quick brown fox jumps over the lazy cog") ==
        bytes.fromhex("de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"))
assert(sha1(b"") ==
        bytes.fromhex("da39a3ee5e6b4b0d3255bfef95601890afd80709"))
