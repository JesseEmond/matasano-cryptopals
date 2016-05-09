from Crypto.Cipher import AES
from xor import xor_bytes


class BadPaddingException(Exception):
    pass


def aes_encrypt_block(key, block):
    assert(len(block) == 16)
    suite = AES.new(key, AES.MODE_ECB)
    return suite.encrypt(block)


def aes_decrypt_block(key, block):
    assert(len(block) == 16)
    suite = AES.new(key, AES.MODE_ECB)
    return suite.decrypt(block)


def ecb_encrypt(key, plaintext):
    blocks = get_blocks(pad(plaintext))
    ciphertext = bytearray()
    for block in blocks:
        ciphertext.extend(aes_encrypt_block(key, block))
    return bytes(ciphertext)


def ecb_decrypt(key, ciphertext):
    blocks = get_blocks(ciphertext)
    plaintext = bytearray()
    for block in blocks:
        plaintext.extend(aes_decrypt_block(key, block))
    return unpad(bytes(plaintext))


def get_blocks(bytes_, blocksize=16):
    return [bytes_[i:i+blocksize] for i in range(0, len(bytes_), blocksize)]


def cbc_encrypt(key, iv, plaintext):
    blocks = get_blocks(pad(plaintext))
    ciphertext = bytearray()

    for block in blocks:
        encrypted = aes_encrypt_block(key, xor_bytes(iv, block))
        ciphertext.extend(encrypted)
        iv = encrypted

    return bytes(ciphertext)


def cbc_decrypt(key, iv, ciphertext):
    blocks = get_blocks(ciphertext)
    plaintext = bytearray()

    for block in blocks:
        decrypted = aes_decrypt_block(key, block)
        plaintext.extend(xor_bytes(iv, decrypted))
        iv = block

    return unpad(bytes(plaintext))


def pad(bytes_, block_size=16):
    padding = block_size - len(bytes_) % block_size
    return bytes_ + bytes([padding] * padding)


def unpad(bytes_, block_size=16):
    pad_val = bytes_[-1]
    if pad_val > block_size:
        raise BadPaddingException()

    pad = bytes_[-pad_val:]

    if pad != bytes([pad_val] * pad_val):
        raise BadPaddingException()

    return bytes_[:-pad_val]


if __name__ == "__main__":
    assert(pad(bytes()) == bytes([16] * 16))
