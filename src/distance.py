def hamming(a, b):
    assert(len(a) == len(b))

    dist = 0
    for x, y in zip(a, b):
        z = x ^ y
        while z:
            dist += z & 1
            z >>= 1

    return dist


if __name__ == "__main__":
    assert(hamming("this is a test".encode('ascii'),
                   "wokka wokka!!!".encode('ascii')) == 37)
