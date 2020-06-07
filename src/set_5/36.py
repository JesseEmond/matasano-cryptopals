from .. import srp


g = 2
k = 3
N = int.from_bytes(bytes.fromhex("""
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b2
2514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7e
c6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45
b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f3562085
52bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
""".replace("\n", "")), "big")
server = srp.SrpServer(g, k, N)
server.store("jesse", "m0nk3y")

client = srp.SrpClient()
client.connect(server, "jesse", "m0nk3y")
