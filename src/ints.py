import math


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
