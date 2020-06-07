import os
import random


def random_number(bits=None, below=None):
    assert (bits is not None) ^ (below is not None)
    rand = random.SystemRandom()
    if bits is not None:
        return rand.getrandbits(bits)
    elif below is not None:
        return rand.randrange(below)
    assert False


def random_bytes(n):
    return os.urandom(n)
