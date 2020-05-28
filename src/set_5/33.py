import random


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


def dh(p, g):
    a = random.randrange(p)
    A = modexp(g, a, p)
    b = random.randrange(p)
    B = modexp(g, b, p)

    s = modexp(B, a, p)
    assert s == modexp(A, b, p)


p = 37
g = 5
dh(p, g)

p = int.from_bytes(bytes.fromhex("""
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b2
2514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7e
c6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45
b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f3562085
52bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
""".replace("\n", "")), "big")
g = 2
dh(p, g)