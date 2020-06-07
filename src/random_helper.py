import os
import random


def rand_int(bits):
    return random.SystemRandom().getrandbits(bits)


def rand_bytes(n):
    return os.urandom(n)
