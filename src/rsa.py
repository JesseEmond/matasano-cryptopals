from . import byteops
from . import intops
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
        # Pre-computations to be able to use CRT when decrypting:
        self._d_p = self._d % (p - 1)
        self._d_q = self._d % (q - 1)
        self._q_inv = mod.modinv(q, p)
        self._p = p
        self._q = q
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
        # CRT optimization to speed up decryption.
        # https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm
        # See https://crypto.stackexchange.com/a/2580/33570
        m1 = pow(c, self._d_p, self._p)
        m2 = pow(c, self._d_q, self._q)
        h = (self._q_inv * (m1 - m2)) % self._p
        return (m2 + h * self._q) % self.n

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


def attack_pkcs_v1_oracle(is_valid_pkcs_v1_fn, ciphertext, e, n,
                          verbose=False):
    """Recovers the plaintext from a PKCS#1 padding oracle.

    Attack from Bleichenbacher in CRYPTO '98:
    http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf

    Args:
        is_valid_pkcs_v1_fn: Returns whether a ciphertext, when decrypted, has
            valid PKCS#1 padding or not.
        ciphertext: Bytes to decrypt.
        e: RSA encryption exponent.
        n: RSA modulus.
        verbose: Whether we should print status information.

    Returns:
        Decrypted plaintext, still with its PKCS#1 padding.
    """
    oracle_calls = 0

    def oracle(c):
        nonlocal oracle_calls
        if verbose and oracle_calls > 0 and oracle_calls % 100000 == 0:
            print(f"  ({oracle_calls:>7} oracle calls so far)")
        oracle_calls += 1
        return is_valid_pkcs_v1_fn(byteops.int_to_bytes(c))

    k = len(byteops.int_to_bytes(n))
    B = 2**(8 * (k - 2))
    c = int.from_bytes(ciphertext, "big")
    # Step 1: Blinding.
    # Mostly skipped. We already have a PKCS-conforming 'c'.
    if verbose:
        print("Step 1: Verifying inputs, setting up initial values.")
    assert oracle(c)
    # s0 = 1
    c0 = c
    M = {(2*B, 3*B-1)}

    def oracle_s(s):
        return oracle((c0 * pow(s, e, n)) % n)

    # Step 2: Searching for PKCS conforming messages.
    # Step 2.a: Starting the search.
    if verbose:
        print("Step 2: Searching for PKCS-conforming messages.")
        print("Step 2.a: Searching for s1...")
    s = next(s1 for s1 in range(intops.ceil_div(n, 3*B), n) if oracle_s(s1))
    if verbose:
        print(f"  s1={s}")

    i = 1
    while len(M) > 1 or next(iter(M))[0] != next(iter(M))[1]:
        if verbose:
            print(f"  i={i}")
            print(f"  |M|={len(M)}")
        if len(M) > 1:
            # Step 2.b: Searching with more than one interval left.
            if verbose:
                print(f"Step 2.b: Searching for s{i}...")
            s = next(si for si in range(s+1, n) if oracle_s(si))
            if verbose:
                print(f"  s{i}={s}")
        else:
            # Step 2.c: Searching with one interval left.
            if verbose:
                print("Step 2.c: Searching with one interval for (r,s)...")
            a, b = next(iter(M))
            if verbose:
                print(f"  interval size: {(b-a).bit_length()} bits")
            found = False
            r = intops.ceil_div(2 * (b*s - 2*B), n)
            while not found:
                s_min = intops.ceil_div(2*B + r*n, b)
                s_max = intops.ceil_div(3*B + r*n, a)
                for new_s in range(s_min, s_max):
                    if oracle_s(new_s):
                        found = True
                        break
                r += 1
            s = new_s
            if verbose:
                print(f"  r={r}")
                print(f"  s={s}")
        # Step 3: Narrowing the set of solutions.
        print("Step 3: Narrowing the set of solutions.")
        new_M = set()
        for a, b in M:
            r_min = intops.ceil_div(a*s-3*B+1, n)
            r_max = intops.ceil_div(b*s-2*B, n)
            for r in range(r_min, r_max+1):
                interval_min = max(a, intops.ceil_div(2*B+r*n, s))
                interval_max = min(b, (3*B-1+r*n) // s)
                if interval_min <= interval_max:  # Not empty.
                    new_M.add((interval_min, interval_max))
        M = new_M

        i += 1
    # Step 4: Computing the solution.
    if verbose:
        print(f"Step 4: Done! Took {oracle_calls} oracle calls.")
    a, b = next(iter(M))
    assert a == b
    m = a  # Because s0 == 1
    if verbose:
        print(f"Plaintext (with PKCS#1): {byteops.int_to_bytes(m)}.")
    return byteops.int_to_bytes(m)


if __name__ == "__main__":
    r = Rsa(e=3, p=3, q=5)
    assert r.decrypt(r.encrypt(4)) == 4
