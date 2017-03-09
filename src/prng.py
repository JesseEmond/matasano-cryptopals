def _int32(n):
    return n & 0xFFFFFFFF


class MT19937:
    def __init__(self, seed=0):
        self._mt = [0] * 624
        self.seed(seed)

    def seed(self, seed):
        self.index = 624
        self._mt[0] = seed
        for i in range(1, 624):
            self._mt[i] = _int32(
                1812433253 * (self._mt[i - 1] ^ self._mt[i - 1] >> 30) + i)

    def random(self):
        if self.index >= 624:
            self._twist()

        y = self._mt[self.index]
        prev = y

        y ^= y >> 11
        y ^= y << 7 & 2636928640
        y ^= y << 15 & 4022730752
        y ^= y >> 18

        self.index += 1

        return _int32(y)

    def _twist(self):
        for i in range(624):
            y = _int32((self._mt[i] & 0x80000000) +
                       (self._mt[(i+1) % 624] & 0x7fffffff))
            self._mt[i] = self._mt[(i + 397) % 624] ^ y >> 1

            if y & 1 == 1:
                self._mt[i] ^= 0x9908b0df
        self.index = 0


def clone_mt19937(outputs):
    assert(len(outputs) >= 624)
    r = random(0)
    r._mt = [untemper(output) for output in outputs[-624:]]
    return r

def untemper(y):
    y = _untemper_right(y, 18)
    y = _untemper_left(y, 15, 4022730752)
    y = _untemper_left(y, 7, 2636928640)
    y = _untemper_right(y, 11)
    return _int32(y)

def _untemper_right(y, bits):
    """
    8-bits example:
    10101010 y
    00010101 y >> 3
    10111111 y' = y ^ y >> 3

    We know the first 3 bits of y' are the same as y's.
    We know these need to be xored with the next 3 bits of y'.
    From the result, we get the second 3 bits of y.
    We can repeat for all the bits up until the point that we go through all
    of y.
    """
    mask = ((1 << bits) - 1) << (32 - bits)
    original = y
    to_xor = 0
    while mask > 0:
        original ^= to_xor
        original_bits = original & mask
        mask >>= bits
        to_xor = original_bits >> bits
    return original

def _untemper_left(y, bits, const):
    """
    8-bits example:
    10101010 y
    01010000 y << 3
    00011000 &
    10111010 y'
    """
    mask = (1 << bits) - 1
    original = y
    to_xor = 0
    while mask & 0xFFFFFFFF > 0:
        original ^= to_xor & const
        original_bits = original & mask
        mask <<= bits
        to_xor = original_bits << bits
    return original

random = MT19937

_y = 0xABCDEF01
_c = 2636928640
assert(_untemper_right(_y ^ _y >> 18, 18) == _y)
assert(_untemper_left(_y ^ _y << 7 & _c, 7, _c) == _y)

_r = random(12)
_out = [_r.random() for _ in range(1000)]
_clone = clone_mt19937(_out)
assert(_clone.random() == _r.random())

# Apparently CPython's random does not allow us to seed with an int like
# this... It does the same treatment for 32-bit ints that it does to
# arbitrarily big ones -- see:
# https://hg.python.org/cpython/file/tip/Modules/_randommodule.c

# Values extracted with C++'s std::mt19937
_rand = random(0)
assert(_rand.random() == 2357136044)
for _ in range(1000): _rand.random()
assert(_rand.random() == 1193028842)
