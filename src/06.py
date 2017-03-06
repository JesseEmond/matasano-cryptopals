from distance import hamming
from base64 import b64decode
from xor import xor_single_char_key, xor_repeating_key, break_xor_char_key
from frequency import english_test


def guess_keysize(cipher):
    def score(cipher, size):
        distances = [hamming(cipher[i * size:(i+1) * size],
                             cipher[(i+1) * size:(i+2) * size])
                     for i in range(len(cipher) // size - 2)]
        return sum(distances) / len(distances) / size

    return min(range(2, 41), key=lambda size: score(cipher, size))


def brute(cipher):
    size = guess_keysize(cipher)
    print("guessed keysize %i" % size)

    blocks = [cipher[i * size:(i+1) * size]
              for i in range(len(cipher) // size)]
    nth_bytes = zip(*blocks)
    key = [break_xor_char_key(bytes_) for bytes_ in nth_bytes]

    return bytes(key)


with open("06.txt") as f:
    lines = f.readlines()

cipher = b64decode(''.join(lines))
key = brute(cipher)
print("key : %s" % key.decode('ascii'))

decrypted = xor_repeating_key(cipher, key)
message = decrypted.decode('ascii')
print(message)

assert(message.startswith("I'm back and I'm ringin' the bell"))
