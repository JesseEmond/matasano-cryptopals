"""Functions around finding roots (function)."""

import math

from . import polynomial


def iroot(n, p):
    """Computes the pth integer root of n. Gives floor(sqrt(n)).

    Based on the Newton method. Takes O(lg lg n) iterations.

    See the following links for details about the algorithm and runtime proofs:
    https://www.akalin.com/computing-isqrt
    https://www.akalin.com/computing-iroot
    """
    if n == 0: return 0
    if p >= n.bit_length(): return 1
    x_0 = 1 << (math.ceil(n.bit_length() / p))  # 2^(ceil(bits(n) / p))
    prev_x = x_0
    while True:
        x = ((p - 1) * prev_x + n // pow(prev_x, p - 1)) // p
        if x >= prev_x: return prev_x
        prev_x = x
assert iroot(64, 3) == 4
assert iroot(65, 3) == 4
assert iroot(1337**15, 15) == 1337


def solve_pow_with_suffix(bytes_suffix, n):
    """Finds xs, if any, such that x**n has the provided suffix (in bytes)."""
    assert n > 0
    suffix = int.from_bytes(bytes_suffix, "big")
    # f(x) = x**n - suffix
    # By finding roots of 'f' mod 2**bitlen(bytes_suffix), we are finding values
    # for which x**n will have the provided suffix, in bytes.
    coefficients = [-suffix] + [0] * (n - 1) + [1]  # x**n - suffix
    f = polynomial.Polynomial(coefficients)
    bits = len(bytes_suffix) * 8
    return polynomial.hensel_lift(f, p=2, k=bits)
assert solve_pow_with_suffix(b"\x02", n=3) == []
assert set(solve_pow_with_suffix(b"\x18", n=3)) == set([0x36, 0xb6, 0x76, 0xf6])
assert solve_pow_with_suffix(b"\x12", n=3) == []
assert solve_pow_with_suffix(b"\x15", n=3) == [0x8d]
