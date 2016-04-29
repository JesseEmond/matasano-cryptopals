from aes import pad


expected = "YELLOW SUBMARINE\x04\x04\x04\x04".encode('ascii')
padded = pad("YELLOW SUBMARINE".encode('ascii'), 20)
assert(expected == padded)
