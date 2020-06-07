from .. import byteops
from .. import dh
from .. import srp


def predict_s(server, username, A, s):
    salt, _ = server.connect(username, A)
    session_key = byteops.int_to_bytes(s)
    hmac = srp.hmac_s(salt, session_key)
    server.validate(username, hmac)


N = dh.MODP_PRIME_1536
server = srp.SrpServer(g=2, k=3, N=N)
server.store("jesse", "m0nk3y")


# With A=0, the server will do:
# s = (A v^u)^b mod N
#   = (0 v^u)^b mod N
#   =         0 mod N
predict_s(server, "jesse", A=0, s=0)

# Same for A=N or other multiples:
predict_s(server, "jesse", A=N, s=0)
predict_s(server, "jesse", A=5*N, s=0)
