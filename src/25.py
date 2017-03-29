from base64 import b64decode
from os import urandom

from aes import ctr_encrypt, ctr_decrypt
from xor import xor_bytes


def edit(ciphertext, key, offset, newtext):
    key, nonce = key
    plaintext = ctr_decrypt(key, nonce, ciphertext)
    plaintext = plaintext[:offset] + newtext + plaintext[offset+len(newtext):]
    return ctr_encrypt(key, nonce, plaintext)


with open("25.txt") as f:
    # not sure what we mean by the recovered plaintext from the ECB exercice,
    # but let's assume that this is our plaintext...
    secret = b64decode(f.read())

key = urandom(16)
nonce = int.from_bytes(urandom(8), byteorder='big')
ciphertext = ctr_encrypt(key, nonce, secret)

# could do block per block, but let's do it all at once...
edited = edit(ciphertext, (key, nonce), 0, bytes([0] * len(ciphertext)))

# 0 ^ keystream gives us our keystream!
keystream = edited
plaintext = xor_bytes(keystream, ciphertext)

assert(plaintext == secret)
