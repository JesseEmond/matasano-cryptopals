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

    def sign(self, m):
        return self.decrypt(m)

    def verify(self, signature):
        return self.encrypt(signature)


def attack_parity_oracle(parity_oracle_fn, ciphertext, e, n, hollywood=False):
    """From oracle that says if plaintext is even or odd, recover plaintext.

    Makes lg(n) calls to the oracle function.

    Args:
        parity_oracle_fn: Function that takes in ciphertext (bytes) and returns
            a boolean saying if the decrypted plaintext is even.
        ciphertext: Bytes to decrypt.
        e: RSA encryption exponent.
        n: RSA modulus.
        hollywood: If we should display the upper bound at every bit.

    Returns:
        Decrypted plaintext.
    """
    c = int.from_bytes(ciphertext, "big")
    # Note that we explicitly keep track of numerators/denominators, because if
    # we just keep track of lower/upper bound values (not always ints), we lose
    # precision from truncation and end up with invalid last few bytes.
    lower, upper = 0, 1
    denominator = 1
    multiplier = pow(2, e, n)
    for i in range(n.bit_length()):
        c = (c * multiplier) % n
        delta = upper - lower
        lower *= 2
        upper *= 2
        denominator *= 2
        if parity_oracle_fn(byteops.int_to_bytes(c)):
            # Is even, so did not wrap our odd modulus. Halve our upper bound.
            upper -= delta
        else:
            # Is odd, so we wrapped. Halve our lower bound.
            lower += delta
        plaintext = n * upper // denominator
        if hollywood:
            print(f"{str(i).zfill(4)}: {byteops.int_to_bytes(plaintext)}")
    return byteops.int_to_bytes(plaintext)
