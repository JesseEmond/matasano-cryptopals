from .. import dh
from .. import random_helper


def modexp(base, exp, modulus):
    if modulus == 1: return 0
    result = 1
    base = base % modulus
    # right-to-left
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % modulus
        exp >>= 1
        base = (base * base) % modulus
    return result
        
assert pow(5, 15, 37) == modexp(5, 15, 37)


def dh_exchange(p, g):
    a = random_helper.random_number(below=p)
    A = modexp(g, a, p)
    b = random_helper.random_number(below=p)
    B = modexp(g, b, p)

    s = modexp(B, a, p)
    assert s == modexp(A, b, p)


p = 37
g = 5
dh_exchange(p, g)

p = dh.MODP_PRIME_1536
g = 2
dh_exchange(p, g)
