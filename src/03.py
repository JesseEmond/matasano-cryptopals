from xor import xor_single_char_key, break_xor_char_key


cipher = bytes.fromhex(
    '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
)

key = break_xor_char_key(cipher)
message = xor_single_char_key(cipher, key).decode('ascii')
print(message)
assert("Cooking MC's like a pound of bacon" == message)
