from .. import aes
from .. import byteops
from .. import dh
from .. import random_helper
from .. import sha1


# Note that this should only be known by the client.
# Using this to be able to do an assertion in the MITM attack.
SECRET_MESSAGE = b"YELLOW SUBMARINE"


def secret_to_key(s):
    return sha1.sha1(byteops.int_to_bytes(s))[:16]


class Client(dh.DhClient):

    def __init__(self):
        super().__init__(g=2, p=dh.MODP_PRIME_1536)

    def verify(self, server):
        print("C: Sending %s to server." % SECRET_MESSAGE)
        key = secret_to_key(self._s)
        iv = random_helper.rand_bytes(16)
        enc = aes.cbc_encrypt(key, iv, SECRET_MESSAGE)
        enc, iv = server.echo(enc, iv)
        assert aes.cbc_decrypt(key, iv, enc) == SECRET_MESSAGE


class Server(dh.DhServer):

    def echo(self, msg, iv):
        key = secret_to_key(self._s)
        msg = aes.cbc_decrypt(key, iv, msg)
        print("S: Received %s." % msg)
        assert msg == SECRET_MESSAGE
        iv = random_helper.rand_bytes(16)
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
