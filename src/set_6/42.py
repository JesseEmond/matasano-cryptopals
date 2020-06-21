import hashlib
import re

from .. import byteops
from .. import ints
from .. import pkcs1_v1_5
from .. import rsa


def sign(r, msg, bits):
    assert msg != b"hi mom"  # Not allowed!
    digest = hashlib.sha1(msg).digest()
    padded = pkcs1_v1_5.encode_sha1(digest, total_len=bits//8)
    return r.sign(int.from_bytes(padded, "big"))


def validate_prefix_match(r, msg, signature, bits):
    """Looks for hash without making sure that it's right-justified."""
    # I.e. gets hash by parsing ASN.1 blob after matching regex:
    # 0001(ff)+00(.*)
    # From original attack on mailing list:
    # https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/
    padded = r.verify(signature).to_bytes(bits//8, "big")
    m = re.fullmatch(b"\x00\x01\xff+\x00(.*)", padded, re.DOTALL)
    if m is None:
        print("Bad hash format!")
        return False
    digest_info = m.group(1)
    digest = pkcs1_v1_5.get_digest(digest_info)
    return hashlib.sha1(msg).digest() == digest


print("[*] Generating 1024-bit key...")
r = rsa.Rsa(e=3, bits=1024)
print("[*] Signing and testing validation logic...")
hello_world_sign = sign(r, b"hello world!", bits=1024)
assert validate_prefix_match(r, b"hello world!", hello_world_sign, bits=1024)
assert not validate_prefix_match(r, b"hi mom", hello_world_sign, bits=1024)

print("[*] Forging signature that fools logic that only checks prefix...")
target_hash = hashlib.sha1(b"hi mom").digest()
forge_target = pkcs1_v1_5.encode_sha1(target_hash, total_len=1024//8)
# target looks like 0001ffffff...ffff00<digest_info>. We'll remove a bunch of
# 'ff's to leave some space for our imperfect cube root.
# We "shift" digest_info left by quite a bit to make sure that we can find a
# cube root.
strip_len = 85
assert forge_target[3:3+strip_len] == b"\xff" * strip_len
# Filling in with FFs since iroot is giving us floor(cube_root(n)), leaves us
# more numerical space to find a root that has our desired prefix.
forge_target = (forge_target[:3] +
                forge_target[3+strip_len:] +
                b"\xff" * strip_len)
forged_signature = ints.iroot(int.from_bytes(forge_target, "big"), 3)
assert validate_prefix_match(r, b"hi mom", forged_signature, bits=1024)

print("[*] Forging signature for the same validator, crafting it 'by hand'...")
# See https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/
# Let's work with a 3072-bit key (more space to find a root).
# Size of 00<digest_info> for SHA-1 is 36 bytes (288 bits).
# We'll be producing 00 01 FF ... FF 00 <digest_info> <GARBAGE>.
# Reminder that (A-B)^3 = A^3 - 3(A^2)B + 3A(B^2) - B^3.
# So if we can formulate our target as something that looks like that, we can
# just use (A-B) as our forged signature.
# Following Bleichenbacher's notes, we define:
# D := 00 <digest_info>
# N := 2^288 - D  (note 288 comes from size in bits of <digest_info>)
# We assume that N = 0 (mod 3).
# We choose to place D 2072 bits over from the right (numerically, D * 2^2072).
# Our padded version will look like:
# 00 01 FF ... FF <D> <GARBAGE>

# Prefix:
# If we want to only represent the prefix 00 01 FF ... FF (followed by zeros
# since it's just the prefix) numerically, you can do:
# 2^(3072 - 15) - 2^(2072 + 288) = 2^3057 - 2^2360
# '15' is the number of 0 bits in 00 01
# '2072 + 288' is the number of bits for <D> <GARBAGE>
# By doing one minus the other, we can the numerical value for having a series
# of 1s in the positions where we have 01 FF ... FF.

# Numerically:
# Our padded numerical value is thus:
# 2^3057 - 2^2360 + D*2^2072 + garbage
# This can be rewritten as:
# 2^3057 - N*2^2072 + garbage
# The cube root of this is then 2^1019 - (N*2^34/3)

# If we cube it:
# (2^1019 - (N * 2^34 / 3))^3  (note this is of the form (A-B)^3)
# Reminder that (A-B)^3 = A^3 - 3(A^2)B + 3A(B^2) - B^3.
# = (2^1019)^3 - 3*(2^1019)^2*(N*2^34/3) + 3*2^1019*(N*2^34/3)^2 - (N*2^34/3)^3
# = 2^3057 - (3*2^2038*N*2^34/3) + (3*2^1019*N^2*2^68/9) - (N^3*2^102/27)
# = 2^3057 - N*2^2072 + N^2*2^1087/3 - N^3*2^102/27
# This fits the pattern:
# 2^3057A - N*2^2072 + garbage
# So it works!
print("    Generating 3072-bit key...")
r = rsa.Rsa(e=3, bits=3072)
D = pkcs1_v1_5.encode_sha1(target_hash, total_len=1024//8)[-36:]
D = int.from_bytes(D, "big")
N = (1 << 288) - D
assert N % 3 == 0
forged_signature = (1 << 1019) - (N * (1 << 34) // 3)
assert validate_prefix_match(r, b"hi mom", forged_signature, bits=3072)

# TODO do it with fixed suffix (but no check for ff+)
