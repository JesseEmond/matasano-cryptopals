from .. import ints
from .. import mod
from .. import rsa


PRIVATE_MESSAGE = int.from_bytes(b"Hello this is a secret message.", "big")


def capture_messages(e, bits=1024):
    """Returns a list of 'e' (ciphertext, mudolus) pairs."""
    parties = [rsa.Rsa(e=e, bits=bits) for _ in range(e)]
    return [(r.encrypt(PRIVATE_MESSAGE), r.n) for r in parties]


((c_0, n_0), (c_1, n_1), (c_2, n_2)) = capture_messages(e=3)
c = mod.crt(residues=[c_0, c_1, c_2], moduli=[n_0, n_1, n_2])
p = ints.iroot(c, 3)
assert p == PRIVATE_MESSAGE


# TODO try attacking if we use fixed padding.
