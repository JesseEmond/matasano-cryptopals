from .. import dsa
from .. import sha1


with open('src/set_6/44.txt', 'r') as f:
    lines = [line.replace('\n', '') for line in f.readlines() if line.strip()]
    assert len(lines) % 4 == 0

msgs = []
signs = []

for i in range(0, len(lines), 4):
    block = [line[line.index(':')+2:] for line in lines[i:i+4]]
    msg, s, r, m = block
    msg = msg.encode('ascii')
    s, r = int(s), int(r)
    m = bytes.fromhex(m.zfill(len(m) + -len(m) % 2))
    assert sha1.Sha1().update(msg).digest() == m
    msgs.append(msg)
    signs.append((r, s))

p = int("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698"
        "c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50"
        "929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18"
        "ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
g = int("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8d"
        "b53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf49"
        "4aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e9904"
        "1be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)
y = int("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d91"
        "5e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519"
        "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c"
        "1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16)

params = dsa.DsaParams(p, q, g)
public = dsa.Dsa(params, y=y)

d, m, sign, k = dsa.k_reuse(msgs, signs, public)
assert d is not None, "Failed to recover private key."
assert d.sign(m, k=k) == sign
assert sha1.Sha1().update(hex(d._x)[2:].encode()).digest().hex() == \
       "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
