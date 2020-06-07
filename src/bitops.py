def left_rotate(n, b, num_bits=32):
    """Left rotate a num_bits integer n by b bits."""
    mask = (1 << num_bits) - 1
    return ((n << b) | (n >> (num_bits - b))) & mask
assert left_rotate(0b1000, 1) == 0b10000


def bit_not(n, num_bits=32):
	return (1 << num_bits) - 1 - n
assert bit_not(0) == 0xFFFFFFFF
