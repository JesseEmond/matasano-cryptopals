from xor import xor_bytes

s1 = "1c0111001f010100061a024b53535009181c"
s2 = "686974207468652062756c6c277320657965"

b1 = bytes.fromhex(s1)
b2 = bytes.fromhex(s2)

expected = "746865206b696420646f6e277420706c6179"
xored = xor_bytes(b1, b2)
print(xored.hex())

assert(xored.hex() == expected)
