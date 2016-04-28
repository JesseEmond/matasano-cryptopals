from aes import ecb_encrypt, get_blocks
from base64 import b64decode
from os import urandom
from sys import stdout


secret = b64decode(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK")
key = urandom(16)


def guess_blocksize(oracle):
    size = len(oracle(bytes()))

    i = 1
    while size == len(oracle(bytes([0x42] * i))):
        i += 1

    next_size = len(oracle(bytes([0x42] * i)))

    return next_size - size


def is_ecb(oracle, blocksize):
    encrypted = oracle(bytes([0x42] * 3 * blocksize))
    blocks = get_blocks(encrypted, blocksize)
    unique_blocks = len(set(blocks))
    return unique_blocks != len(blocks)


def oracle(input_):
    return ecb_encrypt(key, input_ + secret)


# byte used when padding our input
PADDING_BYTE = 0x42


def get_last_known_block(plaintext, blocksize):
    """
    Returns the last block that we know of the plaintext (or placeholders if
    unknown yet). This is the block used as a prefix when bruteforcing a byte.

    Example 1: if we have bruteforced the following string:
               "thisisatest"
               with a blocksize of 4, this would return:
               "test"

    Example 2: if we have not bruteforced anything yet with a blocksize of 4,
               this would return:
               "BBBB"

    Then, the bruteforce will take the last (blocksize - 1) bytes as a prefix:
    "setA"
    "setB"
    "setC"
    ...
    """
    last_plaintext_block = plaintext[-blocksize:]
    assert(len(plaintext) < blocksize or
           len(last_plaintext_block) == blocksize)

    # missing bytes? pad with a constant padding byte
    padding = bytes([PADDING_BYTE] * (blocksize - len(last_plaintext_block)))

    guessing_block = padding + last_plaintext_block
    assert(len(guessing_block) == blocksize)

    return guessing_block


def target_next_byte(plaintext, blocksize):
    """
    Returns a pair (padding_input, target_block_idx) used to bruteforce the
    next byte.

    'padding_input' is the input that should be fed to the oracle to
    position the next byte we want to bruteforce at the end of a block.

    'target_block_idx' is the index that should be used to get the encrypted
    block once it has gone through the oracle.

    Example 1: nothing guessed yet, blocksize of 4:
               ```
               > target_next_byte(bytes(), 4)
               ("BBB", 0)
               ```
               In the case where we have nothing bruteforced yet, we need to
               pad the first block with the same char used when bruteforcing.

    Example 2: guessed "hello test", blocksize of 4:
               ```
               > target_next_byte("test".encode('ascii'), 4)
               ("BBB", 1)
               ```
               We pad in such a way that the byte after the last 't' ends up
               at the end of a block.
    """
    current_idx = len(plaintext)
    current_block_idx = current_idx // blocksize
    current_idx_in_block = current_idx % blocksize

    padding = blocksize - 1 - current_idx_in_block
    pad = bytes([PADDING_BYTE] * padding)

    return (pad, current_block_idx)


blocksize = guess_blocksize(oracle)
assert(16 == blocksize)

assert(is_ecb(oracle, blocksize))

blocks_count = len(get_blocks(oracle(bytes())))
plaintext = bytearray()

for block_idx in range(blocks_count):
    for byte_idx in range(blocksize):
        last_known_block = get_last_known_block(plaintext, blocksize)

        input_, target_block_idx = target_next_byte(plaintext, blocksize)
        encrypted = oracle(input_)

        target_block = get_blocks(encrypted)[target_block_idx]

        prefix = last_known_block[1:]

        for byte in range(256):
            encrypted_guess = oracle(prefix + bytes([byte]))
            guess = get_blocks(encrypted_guess)[0]

            if target_block == guess:
                plaintext.append(byte)
                stdout.write(chr(byte))
                stdout.flush()
                break
