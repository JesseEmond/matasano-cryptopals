from base64 import b64decode
from os import urandom

from aes import ctr_encrypt


key = urandom(16)
nonce = 0

with open("20.txt") as f:
    secrets = f.readlines()

secrets = [b64decode(secret) for secret in secrets]
expected = secrets
secrets = [ctr_encrypt(key, nonce, secret) for secret in secrets]

min_length = min(len(secret) for secret in secrets)
truncated = [secret[:min_length] for secret in secrets]

concatenated = "".join(truncated)
