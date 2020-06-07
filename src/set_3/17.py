from base64 import b64encode, b64decode

from .. import random_helper
from ..aes import (cbc_encrypt, cbc_decrypt, BadPaddingException, get_blocks,
                   xor_bytes, unpad)



SECRETS = [
"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

KEY = random_helper.random_bytes(16)

def get_secret(secret):
    iv = random_helper.random_bytes(16)
    secret = b64decode(secret)
    return iv, cbc_encrypt(KEY, iv, secret)


def padding_oracle(iv, ciphertext):
    try:
        cbc_decrypt(KEY, iv, ciphertext)
        return True
    except BadPaddingException:
        return False


def decrypt_block(oracle, prev_block, current_block):
    """
    Decryption happens like this:
    block_pre_xor xxxxxxxxxxxxxxxx ^
       prev_block pppppppppppppppp =
        plaintext tttttttttttttttt

    We can play with the prev_block to search for a byte that results in
    valid padding:
    block_pre_xor xxxxxxxxxxxxxxx? ^
       prev_block pppppppppppppppB = (we bruteforce 'B')
        plaintext ttttttttttttttt1

    Once we have the prev_block byte that gives valid padding, we can deduce
    the pre_xor byte '?'.
    """
    current_block_pre_xor = []

    for i in range(len(current_block)):
        valid_bytes = bruteforce_pre_xor_byte(oracle, current_block_pre_xor,
                                              current_block)

        # it is possible that more than one byte gave valid padding -- see the
        # comments on 'determine_last_pre_xor_byte'.
        assert((i == 0 and len(valid_bytes) in [1, 2]) or
               (i > 0 and len(valid_bytes) == 1))
        valid_byte = (valid_bytes[0] if i > 0 else
                      determine_last_pre_xor_byte(oracle, valid_bytes,
                                                  current_block))

        # We now know that:
        # valid_byte ^ pre_xor_byte = padding_byte
        assert(valid_byte is not None)
        padding_byte = get_expected_padding_byte(current_block_pre_xor)
        current_block_pre_xor.insert(0, valid_byte ^ padding_byte)

    return xor_bytes(current_block_pre_xor, prev_block)


def bruteforce_pre_xor_byte(oracle, known_pre_xor, current_block):
    """
    We want to craft the valid ending of the padding with what we
    know of the pre_xor bytes so far:
    ...xxxxx pre_xor    ^
    ...bbbbb prev_block =
    ...ppppp padding
    Thus, we use prev_block = pre_xor ^ padding
    With this crafted ending of the valid padding, we can bruteforce
    the missing first byte of the padding.

    E.g.
    We know some pre_xor bytes:
    pre_xor: ...?xxx
    We want to craft the right padding:
    padding: ...4444
    We can then craft the right bytes for the last 3 bytes of prev_block, but
    we need to bruteforce the 4th last byte.
    """
    valid_bytes = []
    padding_byte = get_expected_padding_byte(known_pre_xor)
    for byte in range(256):
        expected_padding = bytes([padding_byte] * padding_byte)
        padding_ending = xor_bytes(expected_padding[:-1], known_pre_xor)

        padding = bytes([byte]) + padding_ending
        assert(len(padding) == len(expected_padding))

        # we only care about the padding -- we can use anything before it
        prefix = bytes([0] * (16 - len(padding)))

        if oracle(prefix + padding, current_block):
            valid_bytes.append(byte)

    return valid_bytes


def determine_last_pre_xor_byte(oracle, valid_bytes, current_block):
    """
    When bruteforcing the last byte of a block, we have a chance of finding 2
    pre_xor bytes that will give valid padding (especially when bruteforcing
    the last block -- the one with the real padding of the original plaintext).

    E.g.
    With the block: ...55555

    We'll find 2 valid pre_xor bytes:
    - the one that produces ...55551
    - the one that produces ...55555

    To figure out which one produces padding that ends with a '1' (because
    that's what we're looking for when bruteforcing the pre_xor bytes), we only
    have to change the 2nd last byte of the pre_xor bytes to produce junk, so
    that *only* the padding ending with a '1' will pass.

    E.g.
    We change the 2nd last byte, and we end up with:
    - the pre_xor byte that produces ...55541
    - the pre_xor byte that produces ...55545

    Only the first one has valid padding.
    """
    verified_byte = None
    for byte in valid_bytes:
        original_prev_block = bytes([0] * 14 + [0, byte])
        tampered_prev_block = bytes([0] * 14 + [1, byte])

        if (oracle(original_prev_block, current_block) and
                oracle(tampered_prev_block, current_block)):
            assert(verified_byte is None)
            verified_byte = byte

    return verified_byte


def get_expected_padding_byte(known_pre_xor):
    return len(known_pre_xor) + 1


for secret in SECRETS:
    iv, encrypted = get_secret(secret)

    blocks = [bytes(iv)] + get_blocks(encrypted)
    decrypted_blocks = [decrypt_block(padding_oracle, blocks[i-1], blocks[i])
                        for i in range(1, len(blocks))]

    padded_plaintext = b"".join(decrypted_blocks)
    plaintext = unpad(padded_plaintext)

    print(plaintext.decode('ascii'))
    assert(b64encode(plaintext).decode('ascii') == secret)
