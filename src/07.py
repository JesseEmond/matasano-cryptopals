from Crypto.Cipher import AES
from base64 import b64decode


with open("07.txt") as f:
    lines = f.readlines()

cipher = b64decode(''.join(lines))

decryption_suite = AES.new(b"YELLOW SUBMARINE", AES.MODE_ECB)
msg = decryption_suite.decrypt(cipher).decode('utf-8')

print(msg)

assert(msg.startswith("I'm back and I'm ringin' the bell"))
