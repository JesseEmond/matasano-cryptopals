from aes import ctr_decrypt
from base64 import b64decode


secret = ("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2sy"
          "LXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
ciphertext = b64decode(secret)

key = b"YELLOW SUBMARINE"
nonce = 0
plaintext = ctr_decrypt(key, nonce, ciphertext)

print(plaintext)
assert(plaintext == b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")
