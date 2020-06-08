from . import byteops
from . import mod
from . import prime


class Rsa:

    def __init__(self, e, bits=None, p=None, q=None):
        """Creates an RSA key with random bits modulus"""
        assert (bits is not None) ^ (p is not None and q is not None)
        if bits is not None:
            while True:
                p = prime.random_prime(bits // 2)
                q = prime.random_prime(bits // 2)
                if self.try_gen_params(p, q, e):
                    break
        elif p is not None and q is not None:
            assert prime.is_prime(p) and prime.is_prime(q)
            assert self.try_gen_params(p, q, e)
        else:
            raise NotImplementedError()

    def try_gen_params(self, p, q, e):
        self.n = p * q
        self.e = e
        totient = (p - 1) * (q - 1)
        if mod.gcd(totient, e) != 1:
            return False
        self._d = mod.modinv(e, totient)
        return True

    def public_key(self):
        """(e, n)"""
        return self.e, self.n

    def _private_key(self):
        """(d, n)"""
        return self._d, self.n

    def encrypt(self, m):
        assert m < self.n
        return pow(m, self.e, self.n)

    def encrypt_bytes(self, m):
        m = int.from_bytes(m, "big")
        c = self.encrypt(m)
        return byteops.int_to_bytes(c)

    def decrypt(self, c):
        assert c < self.n
        return pow(c, self._d, self.n)

    def decrypt_bytes(self, c):
        c = int.from_bytes(c, "big")
        m = self.decrypt(c)
        return byteops.int_to_bytes(m)
