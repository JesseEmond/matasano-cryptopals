from string import ascii_lowercase, ascii_uppercase, digits


table = ascii_uppercase + ascii_lowercase + digits + '+/'


def b64encode(bytes_):
    padding = len(bytes_) % 3
    bytes_ += bytes([0x00] * padding)
    assert(len(bytes_) % 3 == 0)

    encoded = bytearray()

    for i in range(0, len(bytes_), 3):
        block = (bytes_[i] << 16) + (bytes_[i+1] << 8) + bytes_[i+2]

        idx1 = (block & 0b111111000000000000000000) >> 18
        idx2 = (block & 0b000000111111000000000000) >> 12
        idx3 = (block & 0b000000000000111111000000) >> 6
        idx4 = (block & 0b000000000000000000111111)
        indices = [idx1, idx2, idx3, idx4]
        assert(all([idx < len(table) for idx in indices]))

        encoded.extend(bytes([ord(table[idx]) for idx in indices]))

    # replace padding placeholders with padding symbols
    if padding > 0:
        encoded = encoded[:-padding] + bytes([ord('=')] * padding)

    return encoded.decode('ascii')
