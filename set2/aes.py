from Crypto.Cipher import AES


def ecb_encrypt(key, block):
    suite = AES.new(key, AES.MODE_ECB)
    return suite.encrypt(pad(block))


def ecb_decrypt(key, block):
    suite = AES.new(key, AES.MODE_ECB)
    return suite.decrypt(block)


def get_blocks(bytes_):
    return [bytes_[i:i+16] for i in range(0, len(bytes_), 16)]


def xor_blocks(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


def cbc_encrypt(key, iv, plaintext):
    blocks = get_blocks(pad(plaintext))
    ciphertext = bytearray()

    for block in blocks:
        encrypted = ecb_encrypt(key, xor_blocks(iv, block))
        ciphertext.extend(encrypted)
        iv = encrypted

    return bytes(ciphertext)


def cbc_decrypt(key, iv, ciphertext):
    blocks = get_blocks(ciphertext)
    plaintext = bytearray()

    for block in blocks:
        decrypted = ecb_decrypt(key, block)
        plaintext.extend(xor_blocks(iv, decrypted))
        iv = block

    return bytes(plaintext)


def pad(bytes_, block_size=16):
    padding = (block_size - len(bytes_) % block_size) % block_size
    return bytes_ + bytes([padding] * padding)
