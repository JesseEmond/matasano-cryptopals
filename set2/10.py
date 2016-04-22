from aes import ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt
from base64 import b64decode


key = "YELLOW SUBMARINE"

test_block = bytes([0x40] * 16)
assert(test_block == ecb_decrypt(key, ecb_encrypt(key, test_block)))

with open("10.txt") as f:
    ciphertext = b64decode(''.join([line.strip() for line in f.readlines()]))

iv = bytes([0x00] * 16)
decrypted = cbc_decrypt(key, iv, ciphertext)

print(decrypted.decode('ascii'))

assert(ciphertext == cbc_encrypt(key, iv, decrypted))
