from .. import dh
from .. import srp


g = 2
k = 3
N = dh.MODP_PRIME_1536
server = srp.SrpServer(g, k, N)
server.store("jesse", "m0nk3y")

client = srp.SrpClient()
client.connect(server, "jesse", "m0nk3y")
