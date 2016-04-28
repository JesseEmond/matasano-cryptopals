from aes import ecb_encrypt, get_blocks
from base64 import b64decode
from os import urandom
from sys import stdout
from math import ceil


SECRET = b64decode(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK")
KEY = urandom(16)
PREFIX_LEN = urandom(1)[0]
PREFIX = urandom(PREFIX_LEN)


def find_blocksize(oracle):
    size = len(oracle(bytes()))

    i = 1
    while size == len(oracle(bytes([0] * i))):
        i += 1

    next_size = len(oracle(bytes([0] * i)))

    return next_size - size


def has_duplicates(list_):
    return len(list_) != len(set(list_))


def find_prefix_len(oracle, blocksize):
    input_len = 2 * blocksize

    # increase input until we generate 2 identical blocks
    while True:
        # test with 2 different blocks to make sure that we're not using the
        # last bytes from the prefix
        input1 = bytes([0] * input_len)
        input2 = bytes([1] * input_len)
        blocks1 = get_blocks(oracle(input1), blocksize)
        blocks2 = get_blocks(oracle(input2), blocksize)

        if has_duplicates(blocks1) and has_duplicates(blocks2):
            break

        input_len += 1

    # find the index where the first of these 2 identical blocks is
    blocks = get_blocks(oracle(bytes([0] * input_len)), blocksize)
    first_idx = [i * blocksize for i in range(len(blocks)-1)
                 if blocks[i] == blocks[i+1]][0]

    padding = input_len - 2 * blocksize

    return first_idx - padding


def is_ecb(oracle, blocksize):
    encrypted = oracle(bytes([0x42] * 3 * blocksize))
    blocks = get_blocks(encrypted, blocksize)
    return has_duplicates(blocks)


def oracle(input_):
    return ecb_encrypt(KEY, PREFIX + input_ + SECRET)


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


blocksize = find_blocksize(oracle)
assert(16 == blocksize)

assert(is_ecb(oracle, blocksize))

prefix_len = find_prefix_len(oracle, blocksize)
prefix_padding_len = (blocksize - prefix_len % blocksize) % blocksize
prefix_padding = bytes([0] * prefix_padding_len)
prefix_blocks_len = (prefix_len + prefix_padding_len) // blocksize
assert(PREFIX_LEN == prefix_len)

blocks_count = ceil((len(oracle(bytes())) - prefix_len) / blocksize)
plaintext = bytearray()

for block_idx in range(blocks_count):
    for byte_idx in range(blocksize):
        last_known_block = get_last_known_block(plaintext, blocksize)

        input_, target_block_idx = target_next_byte(plaintext, blocksize)
        target_block_idx += prefix_blocks_len
        encrypted = oracle(prefix_padding + input_)

        target_block = get_blocks(encrypted, blocksize)[target_block_idx]

        block_prefix = last_known_block[1:]

        for byte in range(256):
            ciphertext_guess = block_prefix + bytes([byte])
            encrypted_guess = oracle(prefix_padding + ciphertext_guess)
            guess = get_blocks(encrypted_guess, blocksize)[prefix_blocks_len]

            if target_block == guess:
                plaintext.append(byte)
                stdout.write(chr(byte))
                stdout.flush()
                break
