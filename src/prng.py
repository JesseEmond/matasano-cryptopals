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

            if y % 2 != 0:
                self._mt[i] ^= 0x9908b0df
        self.index = 0


random = MT19937

# Apparently CPython's random does not allow us to seed with an int like
# this... It does the same treatment for 32-bit ints that it does to
# arbitrarily big ones -- see:
# https://hg.python.org/cpython/file/tip/Modules/_randommodule.c

# Values extracted with C++'s std::mt19937
_rand = random(0)
assert(_rand.random() == 2357136044)
for _ in range(1000): _rand.random()
assert(_rand.random() == 1193028842)
