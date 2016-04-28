from Crypto.Cipher import AES


class BadPaddingException(Exception):
    pass


def ecb_encrypt_block(key, block):
    suite = AES.new(key, AES.MODE_ECB)
    return suite.encrypt(block)


def ecb_decrypt_block(key, block):
    suite = AES.new(key, AES.MODE_ECB)
    return suite.decrypt(block)


def ecb_encrypt(key, plaintext):
    blocks = get_blocks(pad(plaintext))
    ciphertext = bytearray()
    for block in blocks:
        ciphertext.extend(ecb_encrypt_block(key, block))
    return bytes(ciphertext)


def ecb_decrypt(key, ciphertext):
    blocks = get_blocks(ciphertext)
    plaintext = bytearray()
    for block in blocks:
        plaintext.extend(ecb_decrypt_block(key, block))
    return bytes(plaintext)


def get_blocks(bytes_, blocksize=16):
    return [bytes_[i:i+blocksize] for i in range(0, len(bytes_), blocksize)]


def xor_blocks(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


def cbc_encrypt(key, iv, plaintext):
    blocks = get_blocks(pad(plaintext))
    ciphertext = bytearray()

    for block in blocks:
        encrypted = ecb_encrypt_block(key, xor_blocks(iv, block))
        ciphertext.extend(encrypted)
        iv = encrypted

    return bytes(ciphertext)


def cbc_decrypt(key, iv, ciphertext):
    blocks = get_blocks(ciphertext)
    plaintext = bytearray()

    for block in blocks:
        decrypted = ecb_decrypt_block(key, block)
        plaintext.extend(xor_blocks(iv, decrypted))
        iv = block

    return bytes(plaintext)


def pad(bytes_, block_size=16):
    padding = (block_size - len(bytes_) % block_size) % block_size
    return bytes_ + bytes([padding] * padding)


def unpad(bytes_, block_size=16):
    pad_val = bytes_[-1]

    if pad_val < block_size:
        pad = bytes_[-pad_val:]

        if pad != bytes([pad_val] * pad_val):
            raise BadPaddingException()

        return bytes_[:-pad_val]
    else:
        return bytes_
