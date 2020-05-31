import random


class DhExchange:

    def __init__(self, p, g):
        self.p = p
        self.g = g
        a = random.randrange(p)
        self.A = pow(g, a, p)
        b = random.randrange(p)
        self.B = pow(g, b, p)

        self._s = pow(self.A, b, p)
        assert self._s == pow(self.B, a, p)  # Normal DH here

    def predict_s(self, predicted_s):
        assert predicted_s == self._s


p = int.from_bytes(bytes.fromhex("""
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b2
2514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7e
c6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45
b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f3562085
52bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
""".replace("\n", "")), "big")


# With g=1:
# s = g^a^b mod p = 1^a^b mod p = 1 mod p
DhExchange(p, g=1).predict_s(1)

# With g=p:
# s = g^a^b mod p
#   = p^a^b mod p
#   = 0 mod p
DhExchange(p, g=p).predict_s(0)
# Note that it's the same for g=0.
DhExchange(p, g=0).predict_s(0)

# With g=p-1:
# s = g^a^b mod p
#   = (p-1)^a^b mod p
#   = -1 ^ a ^ b mod p
#   = { 1 if a*b is even
#     { -1 if a*b is odd
dh = DhExchange(p, g=p-1)
# We can know if 'a'&'b' were even or odd in a similar way:
a_odd = dh.A == p-1
b_odd = dh.B == p-1
ab_odd = a_odd and b_odd
dh.predict_s(p-1 if ab_odd else 1)