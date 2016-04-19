from xor import xor_single_char_key
from freq import english_test


def best_message(cipher):
    possible_keys = range(256)
    possible_msgs = [xor_single_char_key(cipher, key) for key in possible_keys]
    message = max(possible_msgs, key=english_test)
    return message


with open("4.txt") as f:
    ciphers = [bytes.fromhex(line.strip()) for line in f.readlines()]

message = max([best_message(cipher) for cipher in ciphers],
              key=english_test).decode('ascii')

print(message)
