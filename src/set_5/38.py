import hashlib

from .. import byteops
from .. import dh
from .. import random_helper
from .. import srp


class Client:

    def __init__(self, password):
        self._password = password
    
    def connect(self, server):
        a = random_helper.random_number(below=server.n)
        A = pow(server.g, a, server.n)
        salt, B, u = server.connect(A)
        x = srp.password_hash(salt, self._password)
        s = pow(B, a + u * x, server.n)
        self._key = hashlib.sha256(byteops.int_to_bytes(s)).digest()
        hmac = srp.hmac_s(salt, self._key)
        server.validate(hmac)


class Server:

    def __init__(self, password, g, n):
        self.g = g
        self.n = n
        self._salt = byteops.int_to_bytes(random_helper.random_number(bits=64))
        x = srp.password_hash(self._salt, password)
        self._v = pow(g, x, n)

    def connect(self, A):
        u = random_helper.random_number(bits=128)
        b = random_helper.random_number(below=self.n)
        B = pow(self.g, b, self.n)
        s = pow(A * pow(self._v, u, self.n), b, self.n)
        self._key = hashlib.sha256(byteops.int_to_bytes(s)).digest()
        return self._salt, B, u

    def validate(self, hmac):
        assert hmac == srp.hmac_s(self._salt, self._key)


class Mitm(Server):

    def __init__(self, client, server):
        self.client = client
        self.real_server = server
        self.n = server.n
        self.g = server.g

    def connect(self, A):
        self.A = A
        # Replace 'B' with ours, one where we'll know 'b'.
        self.b = random_helper.random_number(below=self.n)
        B = pow(self.g, self.b, self.n)
        self.salt, _, self.u = self.real_server.connect(A)
        return self.salt, B, self.u

    def validate(self, hmac):
        self.hmac = hmac  # this is our brute-force target.
        pass  # Always good :)


# Assume we can't see that password. It's taken from the dictionary 38.txt.
client = Client("september")
server = Server("september", g=2, n=dh.MODP_PRIME_1536)
client.connect(server)

# Now MITM to pass some fixed values. We can then brute-force.
mitm = Mitm(client, server)
client.connect(mitm)

with open("src/set_5/38.txt") as f:
    passwords = [password.strip() for password in f.readlines()]

for password in passwords:
    x = srp.password_hash(mitm.salt, password)
    v = pow(mitm.g, x, mitm.n)
    s = pow(mitm.A * pow(v, mitm.u, mitm.n), mitm.b, mitm.n)
    key = hashlib.sha256(byteops.int_to_bytes(s)).digest()
    if srp.hmac_s(mitm.salt, key) == mitm.hmac:
        break  # Found the password!

# Should be able to connect with that password now. :)
Client(password).connect(server)
