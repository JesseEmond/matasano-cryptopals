from .. import pkcs1_v1_5
from .. import rsa


r = rsa.Rsa(e=3, bits=256)


def pkcs_v1_oracle(ciphertext):
    plaintext = r.decrypt_bytes(ciphertext)
    try:
        pkcs1_v1_5.encrypt_unpad(plaintext, 256//8)
        return True
    except ValueError:
        return False


ciphertext = r.encrypt_bytes(pkcs1_v1_5.encrypt_pad(b"kick it, CC", 256//8))
e, n = r.public_key()
plaintext = rsa.attack_pkcs_v1_oracle(pkcs_v1_oracle, ciphertext, e, n,
                                      verbose=True)
plaintext = pkcs1_v1_5.encrypt_unpad(plaintext, 256//8)
print(plaintext)
assert plaintext == b"kick it, CC", plaintext
