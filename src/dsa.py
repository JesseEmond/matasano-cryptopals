import math

from . import byteops
from . import mod
from . import prime
from . import random_helper
from . import sha1


def H(a):
    bytes_ = byteops.int_to_bytes(a)
    digest = sha1.Sha1().update(bytes_).digest()
    return int.from_bytes(digest, byteorder="big")


class DsaParams:

    def generate(L, N, seedlen):
        """Following FIPS 186. Using SHA-1.

        Args:
            L: Desired length of prime p, in bits.
            N: Desired length of prime q, in bits.
            seedlen: Desired length of the domain parameter seed. Must be >= N.
        """
        assert seedlen >= N
        outlen = sha1.Sha1.OUT_LEN * 8
        assert N <= outlen
        # Normally, we should check that (L, N) pairs are in a pre-approved
        # list. Allow unsafe pairs for learning purposes.
        n = math.ceil(L / outlen) - 1
        b = L - 1 - (n * outlen)
        while True:
            seed = random_helper.random_number(bits=seedlen)
            U = H(seed) % 2**(N-1)
            q = 2**(N-1) + U + 1 - (U % 2)
            if prime.is_prime(q):
                offset = 1
                for counter in range(4 * L - 1):
                    V = [H(seed + offset + j) % 2**seedlen for j in range(n+1)]
                    W = (sum(V[j] * 2**(j * outlen) for j in range(n)) +
                         (V[n] % 2**b) * 2**(n * outlen))
                    X = W + 2**(L-1)
                    c = X % (2*q)
                    p = X - (c - 1)
                    if p >= 2**(L-1) and prime.is_prime(p):
                        return DsaParams(p, q)
                    offset += n + 1

    def __init__(self, p, q, g=None):
        self.p = p
        self.q = q
        self.g = g
        if g is None:
            for h in range(2, p - 1):
                g = pow(h, (p-1)//q, p)
                if g != 1:
                    self.g = g
                    break
        assert self.g is not None


class Dsa:

    def __init__(self, params, x=None, y=None):
        """x: private key, y: public key"""
        if y is None:
            x = random_helper.random_number(between=[1, params.q-1])
            y = pow(params.g, x, params.p)

        self.params = params
        self._x = x
        self.y = y

    def sign(self, m, h=None, k=None):
        assert self._x is not None
        if h is None:
            h = H(m)
        while True:
            k = k or random_helper.random_number(between=[1, self.params.q-1])
            r = pow(self.params.g, k, self.params.p) % self.params.q
            if r != 0:
                k_1 = mod.modinv(k, self.params.q)
                s = (k_1 * (h + self._x * r)) % self.params.q
                if s != 0:
                    return r, s

    def verify(self, m, sign, h=None):
        if h is None:
            h = H(m)
        r, s = sign
        if r <= 0 or r >= self.params.q or s <= 0 or s >= self.params.q:
            return False
        w = mod.modinv(s, self.params.q)
        u1 = (h * w) % self.params.q
        u2 = (r * w) % self.params.q
        v = ((pow(self.params.g, u1, self.params.p) *
              pow(self.y, u2, self.params.p)) % self.params.p) % self.params.q
        return v == r


if __name__ == "__main__":
    # Toy example from:
    # http://www.herongyang.com/Cryptography/DSA-Introduction-Algorithm-Illustration-p7-q3.html
    params = DsaParams(p=7, q=3, g=4)
    dsa = Dsa(params, x=5, y=2)
    sign = dsa.sign(m=None, h=3, k=2)
    assert dsa.verify(m=None, sign=sign, h=3)

    # Fixed params from Cryptopals #43.
    p = int("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65ea"
            "c698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565"
            "f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d"
            "2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1",
            16)
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = int("0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4"
            "046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025"
            "e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887"
            "892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291",
            16)
    dsa = Dsa(DsaParams(p, q, g))
    sign = dsa.sign(42)
    assert dsa.verify(42, sign)

    # Param generation.
    params = DsaParams.generate(L=1024, N=160, seedlen=200)
    dsa = Dsa(params)
    sign = dsa.sign(42)
    assert dsa.verify(42, sign)
