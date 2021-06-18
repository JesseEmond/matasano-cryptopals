from .. import dsa
from .. import mod


p = int("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698"
        "c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50"
        "929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18"
        "ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
# Generate some g that we will overwrite.
# Do this so that y is not trivial when we overwrite g.
d = dsa.Dsa(dsa.DsaParams(p, q))


# With g=0, signer does:
# r = (g^k mod p) mod q
# s = k^(-1) (H(m) + xr) mod q
# So r=0.
# And s has no dependence on the private key anymore!
# s = k^(-1) H(m) mod q

# However, we explicitly prevent r from being 0 in our signing logic, so need
# to pass allow_r_0=True.
d.params.g = 0
print("With g=0:")
r, s = d.sign(m=b"hello", allow_r_0=True)
print(f"Sign('hello'): (r={r}, s={s})")
assert r == 0
# When verifying:
# v = (g^u1 * y^u2 mod p) mod q
# g^u1 will give 0, so v will always be 0, so will allow any 's' we give, for
# any message.
# Here again we need to pass a flag to change our DSA logic to enable the 0s.
assert d.verify(b"hello", (r, s), allow_zeros=True)
assert d.verify(b"hello", (0, 424242), allow_zeros=True)
assert d.verify(b"hi", (0, 424242), allow_zeros=True)


# With g = p+1 = 1 mod p, signer does:
# r = (g^k mod p) mod q
# s = k^(-1) (H(m) + xr) mod q
# So r = 1.
# s = k^(-1) (H(m) + xr) mod q
# => sk = H(m) + x mod q
d.params.g = p + 1
print("With g=p+1:")
r, s = d.sign(m=b"hello")
print(f"Sign('hello'): (r={r}, s={s})")
assert r == 1
# Note that verifying (r, s) would fail, because the g used for y is not the
# same we are using now.

# When verifying:
# v = (g^u1 * y^u2 mod p) mod q
# => v = (y^u2 mod p) mod q
# u2 = r/s mod q
# If we choose some fixed 'z' value and compute:
# r = (y^z mod p) mod q
# s = r/z mod q
# Verification will do:
# v = (y^u2 mod p) mod q
# For us:
# u2 = r/s mod q
# => u2 = r / (r/z) mod q
# => u2 = z mod q
# => v = (y^z mod p) mod q
# => v = r mod q
# So we can craft a signature that looks somewhat normal and will pass
# verification.
z = 2**32 - 5  # Arbitrary.
Zq = mod.GF(q)
r = (Zq(pow(d.y, z, p))).int()
s = (Zq(r) / z).int()
assert d.verify(b"hello", (r, s))
assert d.verify(b"hi", (r, s))
assert d.verify(b"Hello, world", (r, s))
assert d.verify(b"Goodbye, world", (r, s))
