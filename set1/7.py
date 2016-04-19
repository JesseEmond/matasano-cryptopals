from Crypto.Cipher import AES
from base64 import b64decode


with open("7.txt") as f:
    lines = f.readlines()

cipher = b64decode(''.join(lines))

decryption_suite = AES.new("YELLOW SUBMARINE", AES.MODE_ECB)
msg = decryption_suite.decrypt(cipher).decode('utf-8')

print(msg)
