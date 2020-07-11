def left_rotate(n, b, num_bits=32):
    """Left rotate a num_bits integer n by b bits."""
    mask = (1 << num_bits) - 1
    return ((n << b) | (n >> (num_bits - b))) & mask
assert left_rotate(0b1000, 1) == 0b10000


def bit_not(n, num_bits=32):
    return (1 << num_bits) - 1 - n
assert bit_not(0) == 0xFFFFFFFF


def replace_suffix(n, suffix, suffix_len=None):
    """Replaces the last suffix_len bits of 'n' with 'suffix'.

    If 'suffix_len' is not provided, use suffix.bit_length().
    """
    suffix_len = suffix_len or suffix.bit_length()
    assert suffix.bit_length() <= suffix_len
    suffix_mask = (1 << suffix_len) - 1
    # Clear the last bits.
    n ^= n & suffix_mask
    # Set suffix.
    return n | suffix
assert replace_suffix(0b1010101, suffix=0b111) == 0b1010111
assert replace_suffix(0b1010101, suffix=0b111, suffix_len=5) == 0b1000111
