def pad(bytes_, block_size):
    padding = block_size - len(bytes_) % block_size
    return bytes_ + bytes([padding] * padding)

expected = "YELLOW SUBMARINE\x04\x04\x04\x04".encode('ascii')
padded = pad("YELLOW SUBMARINE".encode('ascii'), 20)
assert(expected == padded)
