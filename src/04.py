from xor import xor_single_char_key, break_xor_char_key
from frequency import english_test


with open("04.txt") as f:
    ciphers = [bytes.fromhex(line.strip()) for line in f.readlines()]

message = max([xor_single_char_key(cipher, break_xor_char_key(cipher))
               for cipher in ciphers],
              key=english_test).decode('ascii')

print(message)
assert("Now that the party is jumping\n" == message)
