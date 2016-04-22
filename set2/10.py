from Crypto.Cipher import AES
from base64 import b64decode


def ecb_encrypt(key, block):
    suite = AES.new(key, AES.MODE_ECB)
    return suite.encrypt(block)


def ecb_decrypt(key, block):
    suite = AES.new(key, AES.MODE_ECB)
    return suite.decrypt(block)


def get_blocks(bytes_):
    return [bytes_[i:i+16] for i in range(0, len(bytes_), 16)]


def xor_blocks(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


def cbc_encrypt(key, iv, plaintext):
    blocks = get_blocks(plaintext)
    ciphertext = bytearray()

    for block in blocks:
        encrypted = ecb_encrypt(key, xor_blocks(iv, block))
        ciphertext.extend(encrypted)
        iv = encrypted

    return ciphertext


def cbc_decrypt(key, iv, ciphertext):
    blocks = get_blocks(ciphertext)
    plaintext = bytearray()

    for block in blocks:
        decrypted = ecb_decrypt(key, block)
        plaintext.extend(xor_blocks(iv, decrypted))
        iv = block

    return plaintext


key = "YELLOW SUBMARINE"

test_block = bytes([0x40] * 16)
assert(test_block == ecb_decrypt(key, ecb_encrypt(key, test_block)))

with open("10.txt") as f:
    ciphertext = b64decode(''.join([line.strip() for line in f.readlines()]))

iv = bytes([0x00] * 16)
decrypted = cbc_decrypt(key, iv, ciphertext)

print(decrypted.decode('ascii'))

assert(ciphertext == cbc_encrypt(key, iv, decrypted))
