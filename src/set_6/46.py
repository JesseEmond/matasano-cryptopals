import base64

from .. import byteops
from .. import rsa


def gen_parity_oracle():
    """Returns (parity_oracle_fn, ciphertext, pub_key)."""
    secret = base64.b64decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGF"
                              "yb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")
    r = rsa.Rsa(e=3, bits=1024)
    ciphertext = r.encrypt_bytes(secret)

    def parity_oracle(c):
        p = r.decrypt_bytes(c)
        return p[-1] % 2 == 0

    return parity_oracle, ciphertext, r.public_key()


parity_oracle_fn, ciphertext, (e, n) = gen_parity_oracle()
plaintext = rsa.attack_parity_oracle(parity_oracle_fn, ciphertext, e, n,
                                     hollywood=True)
plaintext = plaintext.decode("ascii")
print(f"Recovered: '{plaintext}'")

assert plaintext == \
        "That's why I found you don't play around with the Funky Cold Medina"
