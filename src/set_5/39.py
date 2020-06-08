from .. import rsa


r = rsa.Rsa(e=3, p=17, q=89)
assert r.decrypt(r.encrypt(42)) == 42
assert r.decrypt_bytes(r.encrypt_bytes(b"\x42")) == b"\x42"

r = rsa.Rsa(e=3, bits=1024)
assert r.decrypt(r.encrypt(1337)) == 1337
assert r.decrypt_bytes(r.encrypt_bytes(b"Hello World!")) == b"Hello World!"
