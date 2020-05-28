from base64 import b64decode
from os import urandom

from ..aes import ctr_encrypt
from ..xor import xor_bytes, rank_xor_repeating_keys


key = urandom(16)
nonce = 0

with open("src/set_3/20.txt") as f:
    secrets = f.readlines()

secrets = [b64decode(secret) for secret in secrets]
expected = secrets
secrets = [ctr_encrypt(key, nonce, secret) for secret in secrets]

min_length = min(len(secret) for secret in secrets)
truncated = [secret[:min_length] for secret in secrets]

concatenated = b"".join(truncated)
keys = rank_xor_repeating_keys(concatenated, min_length)

# found through analysis
key_indices = {
        0: 3,
        }
key = bytes([keys[i][key_indices.get(i, 0)] for i in range(len(keys))])

plaintexts = [xor_bytes(secret, key) for secret in secrets]

for i in range(len(expected)):
    print(plaintexts[i])
    assert(expected[i].startswith(plaintexts[i]))
