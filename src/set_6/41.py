import hashlib

from .. import byteops
from .. import mod
from .. import rsa


class Server:

    def __init__(self):
        self.rsa = rsa.Rsa(e=2**16+1, bits=1024)
        self._hashes = set()

    def encrypt(self, msg):
        return self.rsa.encrypt_bytes(msg)

    def decrypt(self, msg):
        """Note: can only be called once per message."""
        hash_ = hashlib.sha256(msg).digest()
        if hash_ in self._hashes: return None  # Can't!
        self._hashes.add(hash_)
        return self.rsa.decrypt_bytes(msg)


server = Server()

# Requests made by the client we're targetting
PRIVATE_MESSAGE = b"{ time: 1356304276, social: '555-55-5555', }"
intercepted = server.encrypt(PRIVATE_MESSAGE)
assert server.decrypt(intercepted) == PRIVATE_MESSAGE
assert server.decrypt(intercepted) is None  # Only works once.

s = 2  # Anything > 1 mod N
c = int.from_bytes(intercepted, "big")
c_prime = (pow(s, server.rsa.e, server.rsa.n) * c) % server.rsa.n
# s^e * c mod N
# = s^e * p^e mod N
# = (s * p)^e mod N

# p' = s * p mod N
p_prime = int.from_bytes(server.decrypt(byteops.int_to_bytes(c_prime)), "big")
s_inv = mod.modinv(s, server.rsa.n)
p = (p_prime * s_inv) % server.rsa.n
assert byteops.int_to_bytes(p) == PRIVATE_MESSAGE
