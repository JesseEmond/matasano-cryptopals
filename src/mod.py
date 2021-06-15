# Utilities for modular arithmetic.

import math


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
