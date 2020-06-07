def int_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, "big")
assert int_to_bytes(1) == b"\x01"
assert int_to_bytes(0x1ff) == bytes.fromhex("01ff")
