from xor import xor_single_char_key
from frequency import english_test

cipher = bytes.fromhex(
    '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
)


possible_keys = range(256)
possible_msgs = [xor_single_char_key(cipher, key) for key in possible_keys]
message = max(possible_msgs, key=english_test).decode('ascii')
print(message)
assert("Cooking MC's like a pound of bacon" == message)
