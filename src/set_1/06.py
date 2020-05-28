from base64 import b64decode

from ..distance import hamming
from ..xor import (xor_single_char_key, xor_repeating_key,
                   break_xor_repeating_key, guess_key_lengths)
from ..frequency import english_test


with open("src/set_1/06.txt") as f:
    lines = f.readlines()

cipher = b64decode(''.join(lines))

key_length = guess_key_lengths(cipher)[0]
print("guessed key length: %i" % key_length)

key = break_xor_repeating_key(cipher, key_length)
print("key: %s" % key.decode('ascii'))

decrypted = xor_repeating_key(cipher, key)
message = decrypted.decode('ascii')
print(message)

assert(message.startswith("I'm back and I'm ringin' the bell"))
