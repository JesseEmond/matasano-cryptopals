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
    assert(len(iv) == 16)
    blocks = get_blocks(pad(plaintext))
    ciphertext = bytearray()

    for block in blocks:
        encrypted = aes_encrypt_block(key, xor_bytes(iv, block))
        ciphertext.extend(encrypted)
        iv = encrypted

    return bytes(ciphertext)


def cbc_decrypt(key, iv, ciphertext):
    assert(len(iv) == 16)
    blocks = get_blocks(ciphertext)
    plaintext = bytearray()

    for block in blocks:
        decrypted = aes_decrypt_block(key, block)
        plaintext.extend(xor_bytes(iv, decrypted))
        iv = block

    return unpad(bytes(plaintext))


def ctr_encrypt(key, nonce, plaintext):
    nonce = nonce.to_bytes(8, byteorder='little')
    keystream = bytes()
    block_count = 0
    while len(keystream) < len(plaintext):
        block = nonce + block_count.to_bytes(8, byteorder='little')
        keystream += aes_encrypt_block(key, block)
        block_count += 1
    return xor_bytes(plaintext, keystream)


def ctr_decrypt(key, nonce, ciphertext):
    return ctr_encrypt(key, nonce, ciphertext)


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
    key = "YELLOW SUBMARINE".encode('ascii')
    msg = "this is a test please work".encode('ascii')
    iv = b"\x00" * 16
    nonce = 0
    assert(ecb_decrypt(key, ecb_encrypt(key, msg)) == msg)
    assert(cbc_decrypt(key, iv, cbc_encrypt(key, iv, msg)) == msg)
    assert(ctr_decrypt(key, nonce, ctr_encrypt(key, nonce, msg)) == msg)
