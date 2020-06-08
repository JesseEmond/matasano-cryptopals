# Utilities for modular arithmetic.

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
    return t
assert modinv(3, 11) == 4
