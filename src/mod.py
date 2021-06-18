# Utilities for modular arithmetic.

import math

from . import prime


def egcd(a, b):
    """as + bt = gcd(a, b). Returns (gcd(a,b), s, t)"""
    # https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    s, old_s = 0, 1
    r, old_r = b, a
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    bezout_t = (old_r - old_s * a) // b if b != 0 else 0
    return old_r, old_s, bezout_t
assert egcd(46, 240) == (2, 47, -9)


def gcd(a, b):
    r, _, _ = egcd(a, b)
    return r


def modinv(a, n):
    """at = 1 mod n, returns t if gcd(a, n) = 1, otherwise raises ValueError."""
    # ns + at = 1
    # => at = 1 (mod n)
    r, _, t = egcd(n, a)
    if r != 1:
        raise ValueError("a and n are not coprime (gcd(a, n) != 1).")
    return t % n
assert modinv(3, 11) == 4


def coprime(a, b):
    return gcd(a, b) == 1
assert coprime(5, 7)


def pairwise_coprime(xs):
    return all(coprime(xs[i], xs[j])
               for i in range(len(xs))
               for j in range(i+1, len(xs)))
assert pairwise_coprime([5, 7, 9, 4, 13])
assert not pairwise_coprime([2, 5, 7, 9, 15, 4])


def crt(residues, moduli):
    """For pairwise coprime moduli, finds x = residues[i] (mod moduli[i]).

    We have the congruences:
      x = residues[0]  (mod moduli[0])
      x = residues[1]  (mod moduli[1])
      ...
      x = residues[-1]  (mod moduli[-1])
    where moduli[0], moduli[1], ..., moduli[-1] are mutually coprime.
    We're searching for 'x'.

    Let M = product(moduli) and M_i[i] = M // moduli[i].
    Let s[i] = modinv(M_i[i], moduli[i]).
    x = sum(residues[i] * M_i[i] * s[i])  (mod M)

    Also known as the Sun Zi theorem.
    """
    assert pairwise_coprime(moduli)
    assert len(residues) == len(moduli)
    M = math.prod(moduli)
    M_i = [M // modulus for modulus in moduli]
    s = [modinv(M_i, modulus) for M_i, modulus in zip(M_i, moduli)]
    x = sum((residue * M_i * s) % M
            for residue, M_i, s in zip(residues, M_i, s))
    return x % M
assert crt(residues=[1, 4, 6], moduli=[3, 5, 7]) == 34


class GF:
    """Integers mod p^k, for prime p."""

    class GFInt:

        def __init__(self, x, f):
            assert isinstance(x, int), f"x must be an int: {x}"
            self.f = f
            self.x = x % f.p**f.k

        def _conv(self, y):
            if isinstance(y, GF.GFInt) and y.f == self.f:
                return y
            return GF.GFInt(y, self.f)

        def __add__(self, y):
            return GF.GFInt(self.x + self._conv(y).x, self.f)

        def __sub__(self, y):
            return GF.GFInt(self.x - self._conv(y).x, self.f)

        def __rsub__(self, y):
            return GF.GFInt(self._conv(y).x - self.x, self.f)

        def __mul__(self, y):
            return GF.GFInt(self.x * self._conv(y).x, self.f)

        __radd__ = __add__
        __rmul__ = __mul__

        def __truediv__(self, y):
            div_y = modinv(self._conv(y).x, self.f.p**self.f.k)
            return self * div_y

        def __floordiv__(self, y):
            return self / y

        def __neg__(self):
            return GF.GFInt(-self.x, self.f)

        def __pow__(self, y):
            y = y.int() if isinstance(y, GF.GFInt) else y
            return GF.GFInt(pow(self.x, y, self.f.p**self.f.k), self.f)

        def __eq__(self, y):
            y = self._conv(y)
            return self.f == y.f and self.x == y.x

        def __str__(self):
            return f"{self.f}({self.x})"

        def int(self):
            return self.x

    def __init__(self, p, k=1, verify=False):
        if verify:
            assert prime.is_prime(p)
        self.p = p
        self.k = k

    def __call__(self, a):
        return GF.GFInt(a, self)

    def __eq__(self, f):
        return self.p == f.p and self.k == f.k

    def __str__(self):
        if self.k == 1:
            return f"GF({self.p})"
        else:
            return f"GF({self.p}^{self.k})"


if __name__ == "__main__":
    x = GF(5)(17)
    assert x.int() == 2
    x += 2
    assert x.int() == 4
    x -= 6
    assert x.int() == 3
    x *= 2
    assert x.int() == 1
    x /= 4
    assert x.int() == 4, x.int()
    assert (x * 4).int() == 1
    assert x == GF(5)(4)
    assert -x == GF(5)(1)
    assert GF(5)(2)**3 == GF(5)(3)

    # Just make sure we can call reversed versions of fns
    x = GF(5)(0)
    assert x + 2 == GF(5)(2)
    assert 2 + x == GF(5)(2)
    assert x - 1 == GF(5)(4)
    assert 1 - x == GF(5)(1)
