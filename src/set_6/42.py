import hashlib
import re

from .. import byteops
from .. import ints
from .. import pkcs1_v1_5
from .. import rsa


def sign(r, msg):
    assert msg != b"hi mom"  # Not allowed!
    digest = hashlib.sha1(msg).digest()
    padded = pkcs1_v1_5.encode_sha1(digest, total_len=1024//8)
    return r.sign(int.from_bytes(padded, "big"))


def validate_prefix_match(r, msg, signature):
    """Looks for hash without making sure that it's right-justified."""
    # I.e. gets hash by parsing ASN.1 blob after matching regex:
    # 0001(ff)+00(.*)
    # From original attack on mailing list:
    # https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/
    padded = r.verify(signature).to_bytes(1024//8, "big")
    m = re.fullmatch(b"\x00\x01\xff+\x00(.*)", padded, re.DOTALL)
    if m is None:
        print("Bad hash format!")
        return False
    digest_info = m.group(1)
    digest = pkcs1_v1_5.get_digest(digest_info)
    return hashlib.sha1(msg).digest() == digest


print("[*] Generating params...")
r = rsa.Rsa(e=3, bits=1024)
print("[*] Signing and testing validation logic...")
hello_world_sign = sign(r, b"hello world!")
assert validate_prefix_match(r, b"hello world!", hello_world_sign)
assert not validate_prefix_match(r, b"hi mom", hello_world_sign)

print("[*] Forging signature that fools logic that only checks prefix...")
target_hash = hashlib.sha1(b"hi mom").digest()
forge_target = pkcs1_v1_5.encode_sha1(target_hash, total_len=1024//8)
# target looks like 0001ffffff...ffff00<digest_info>. We'll remove a bunch of
# 'ff's to leave some space for our imperfect cube root.
strip_len = 85
assert forge_target[3:3+strip_len] == b"\xff" * strip_len
forge_target = (forge_target[:3] +
                forge_target[3+strip_len:] +
                b"\xff" * strip_len)
forged_signature = ints.iroot(int.from_bytes(forge_target, "big"), 3)
assert validate_prefix_match(r, b"hi mom", forged_signature)

# TODO do it "by hand"

# TODO do it with fixed suffix (but no check for ff+)
