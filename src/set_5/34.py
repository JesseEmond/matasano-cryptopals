import os
import random

from .. import aes
from .. import byteops
from .. import sha1


# Note that this should only be known by the client.
# Using this to be able to do an assertion in the MITM attack.
SECRET_MESSAGE = b"YELLOW SUBMARINE"


def secret_to_key(s):
    return sha1.sha1(byteops.int_to_bytes(s))[:16]


class Client:

    def __init__(self):
        self.p = int.from_bytes(bytes.fromhex("""
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b2
2514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7e
c6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45
b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f3562085
52bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
""".replace("\n", "")), "big")
        self.g = 2

    def initiate_dh(self, server):
        a = random.randrange(self.p)
        A = pow(self.g, a, self.p)
        B = server.respond_dh(self.p, self.g, A)
        self._s = pow(B, a, self.p)

    def verify(self, server):
        print("C: Sending %s to server." % SECRET_MESSAGE)
        key = secret_to_key(self._s)
        iv = os.urandom(16)
        enc = aes.cbc_encrypt(key, iv, SECRET_MESSAGE)
        enc, iv = server.echo(enc, iv)
        assert aes.cbc_decrypt(key, iv, enc) == SECRET_MESSAGE


class Server:

    def respond_dh(self, p, g, A):
        b = random.randrange(p)
        B = pow(g, b, p)
        self._s = pow(A, b, p)
        return B

    def echo(self, msg, iv):
        key = secret_to_key(self._s)
        msg = aes.cbc_decrypt(key, iv, msg)
        print("S: Received %s." % msg)
        assert msg == SECRET_MESSAGE
        iv = os.urandom(16)
        return aes.cbc_encrypt(key, iv, msg), iv


class Mitm(Server):

    def mitm_dh(self, client, server):
        self.real_server = server
        client.initiate_dh(self)

    def respond_dh(self, p, g, A):
        # By pretending that our 'A' is 'p', the server will do
        # s = A^b mod p = p^b mod p = 0 mod p
        # Ignore the real server's 'B'.
        _ = self.real_server.respond_dh(p, g, A=p)
        # Pretend that our 'B' is 'p'. The client will do
        # s = B^a mod p = p^a mod p = 0 mod p
        self._s = 0
        return p


# This on its own should work.
client = Client()
server = Server()

client.initiate_dh(server)
client.verify(server)


# Now let's test our man-in-the-middle attack.
mitm = Mitm()
mitm.mitm_dh(client, server)
client.verify(mitm)
