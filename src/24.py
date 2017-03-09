from os import urandom
from time import time

from xor import xor_bytes
from prng import random


def encrypt_mt19937(seed, plaintext):
    assert(seed < 2**16)
    key_stream = bytearray()
    r = random(seed)
    while len(key_stream) < len(plaintext):
        key_stream.extend(int.to_bytes(r.random(), 4, byteorder='big'))
    return xor_bytes(plaintext, key_stream)


def decrypt_mt19937(seed, ciphertext):
    return encrypt_mt19937(seed, ciphertext)


def generate_mt19937_token():
    seed = int(time())
    return random(seed).random()


def is_mt19937_token(token, time_window=300):
    seed = int(time())
    return any(random(seed + time_diff).random() == token
               for time_diff in range(-time_window, time_window+1))


assert(decrypt_mt19937(42, encrypt_mt19937(42, b"Hello World!")) ==
       b"Hello World!")


known_plaintext = b"A" * 14
# normally we want 16-bits, but it takes too long... the idea is the same here.
secret_seed = int.from_bytes(urandom(1), byteorder='big')
print("Secret seed is: %d" % secret_seed)
hidden_prefix = urandom(urandom(1)[0])
hidden_plaintext = hidden_prefix + known_plaintext
ciphertext = encrypt_mt19937(secret_seed, hidden_plaintext)

valid_seeds = (seed for seed in range(2**16)
               if known_plaintext in decrypt_mt19937(seed, ciphertext))
assert(next(valid_seeds) == secret_seed)
print("Found seed!")

print("Generating token...")
token = generate_mt19937_token()
assert(is_mt19937_token(token))
print("Detected!")

print("Generating fake token...")
token = random(42).random()
assert(not is_mt19937_token(token))
print("Detected!")
