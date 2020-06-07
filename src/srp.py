import hashlib
import random

from . import byteops
from . import mac
from . import random_helper


def scrambling_key(A, B):
    A_B = byteops.int_to_bytes(A) + byteops.int_to_bytes(B)
    uH = hashlib.sha256(A_B).digest()
    return int.from_bytes(uH, "big")


def password_hash(salt, password):
    xH = hashlib.sha256(salt + password.encode('utf-8')).digest()
    return int.from_bytes(xH, "big")


class SrpServer:

    def __init__(self, g, k, N):
        # {I: (salt, v)} = {username: (salt, verifier)}
        self._users = {}
        # {I: session_key}
        self._sessions = {}
        self.g = 2
        self.k = 3
        self.N = N

    def store(self, username, password):
        assert username not in self._users
        salt = byteops.int_to_bytes(random_helper.rand_int(bits=64))
        x = password_hash(salt, password)
        v = pow(self.g, x, self.N)
        self._users[username] = (salt, v)

    def connect(self, username, A):
        salt, v = self._users[username]
        b = random.randrange(self.N)
        B = (self.k * v + pow(self.g, b, self.N)) % self.N
        u = scrambling_key(A, B)
        s = pow(A * pow(v, u, self.N), b, self.N)
        session_key = byteops.int_to_bytes(s)
        self._sessions[username] = session_key
        return salt, B

    def validate(self, username, hmac):
        session_key = self._sessions[username]
        key = hashlib.sha256(session_key).digest()
        salt, _ = self._users[username]
        assert mac.hmac_sha256(key, salt) == hmac
        print("[S] Connection successful!")


class SrpClient:

    def connect(self, server, username, password):
        a = random.randrange(server.N)
        A = pow(server.g, a, server.N)
        salt, B = server.connect(username, A)
        u = scrambling_key(A, B)
        x = password_hash(salt, password)
        s = pow(B - server.k * pow(server.g, x, server.N), a + u * x, server.N)
        self._session_key = byteops.int_to_bytes(s)
        self.validate(server, username, salt)

    def validate(self, server, username, salt):
        key = hashlib.sha256(self._session_key).digest()
        hmac = mac.hmac_sha256(key, salt)
        server.validate(username, hmac)
