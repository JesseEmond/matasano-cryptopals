import hashlib
import re

from .. import bitops
from .. import byteops
from .. import pkcs1_v1_5
from .. import random_helper
from .. import roots
from .. import rsa


def sign(r, msg, bits):
    assert b"hi mom" not in msg  # Not allowed!
    digest = hashlib.sha1(msg).digest()
    padded = pkcs1_v1_5.encode(pkcs1_v1_5.sha1_digest_info(digest),
                               total_len=bits//8)
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


def validate_prefix_suffix(r, msg, signature, bits):
    """Looks for hash without checking the padding bytes."""
    # I.e. gets hash by parsing ASN.1 blob after matching regex:
    # 0001[^00]*00(.*)
    # And ensuring that ASN.1 parsing leaves no leftover bytes.
    # From attack listed on (CVE-2016-1494):
    # https://blog.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/
    # This is one of the tricks used in BERserk.
    padded = r.verify(signature).to_bytes(bits//8, "big")
    m = re.fullmatch(b"\x00\x01[^\x00]*\x00(.*)", padded, re.DOTALL)
    if m is None:
        print("Bad hash format!")
        return False
    digest_info = m.group(1)
    digest = pkcs1_v1_5.get_digest(digest_info, ensure_full_parse=True)
    if digest is None:
        print("Hash is not right-justified!")
        return False
    return hashlib.sha1(msg).digest() == digest


def _forge_cubed_prefix(target_prefix, total_len, padding_len, suffix=b"",
                        forbidden_padding_byte=None):
    """Forges a signature (with suffix) with given target prefix when cubed.

    If specified, will retry until bytes in
    cube[len(target_prefix), -len(suffix)] do not contain the
    forbidden_padding_byte (e.g. if we can't have null bytes in padding).
    Will also retry if the cube we attempt with fixed suffix does not give the
    desired prefix anymore.
    """
    print("    Crafting prefix", end="")
    while True:
        print(".", end="")
        filler_len = total_len - len(target_prefix)
        filler_bytes = random_helper.random_bytes(filler_len)
        sign_target = target_prefix + filler_bytes
        forged = roots.iroot(int.from_bytes(sign_target, "big"), 3)
        suffix_int = int.from_bytes(suffix, "big")
        forged = bitops.replace_suffix(forged, suffix_int,
                                       suffix_len=len(suffix) * 8)
        cube_bytes = (forged**3).to_bytes(total_len, "big")
        if not cube_bytes.startswith(target_prefix):
            # This is unlikely, but if fixing our own suffix changes the upper
            # bytes post-cubing such that it changes the prefix, the filler
            # bytes don't really work for our suffix. We just try again.
            continue
        assert cube_bytes.startswith(target_prefix)  # I think this can happen normally
        padding_start = len(target_prefix)
        padding = cube_bytes[padding_start:padding_start + padding_len]
        if (forbidden_padding_byte is None or
            forbidden_padding_byte not in padding):
            break  # No forbidden bytes in padding, or none were forbidden.
    print()
    if forbidden_padding_byte is not None:
        print("    Found prefix that generates no forbidden padding bytes!")
    return byteops.int_to_bytes(forged)



print("[*] Generating 1024-bit key...")
r = rsa.Rsa(e=3, bits=1024)
print("[*] Signing and testing validation logic...")
hello_world_sign = sign(r, b"hello world!", bits=1024)
assert validate_prefix_match(r, b"hello world!", hello_world_sign, bits=1024)
assert validate_prefix_suffix(r, b"hello world!", hello_world_sign, bits=1024)
assert not validate_prefix_match(r, b"hi mom", hello_world_sign, bits=1024)
assert not validate_prefix_suffix(r, b"hi mom", hello_world_sign, bits=1024)

print("[*] Forging signature that fools logic that only checks prefix...")
target_hash = hashlib.sha1(b"hi mom").digest()
forge_target = pkcs1_v1_5.encode(pkcs1_v1_5.sha1_digest_info(target_hash),
                                 total_len=1024//8)
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
forged_signature = roots.iroot(int.from_bytes(forge_target, "big"), 3)
assert validate_prefix_match(r, b"hi mom", forged_signature, bits=1024)

print("[*] Forging signature for the same validator, crafting it 'by hand'...")
# See https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/
# Let's work with a 3072-bit key (more space to find a root).
# Size of 00<digest_info> for SHA-1 is 36 bytes (288 bits).
# We'll be producing 00 01 FF ... FF 00 <digest_info> <garbage>.
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
# By doing one minus the other, we get the numerical value for having a series
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
# 2^3057 - N*2^2072 + garbage
# So it works!
print("[*] Generating 3072-bit key...")
r = rsa.Rsa(e=3, bits=3072)
D = b"\x00" + pkcs1_v1_5.sha1_digest_info(target_hash).encode()
D = int.from_bytes(D, "big")
N = (1 << 288) - D
assert N % 3 == 0
forged_signature = (1 << 1019) - (N * (1 << 34) // 3)
assert validate_prefix_match(r, b"hi mom", forged_signature, bits=3072)

# What if we had an implementation that verified that ASN.1 parsing had no
# leftover, but didn't check that the padding was 'ff's?
# https://blog.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/
# This is CVE-2016-1494 (python-rsa), where the implementation functionally
# extracted the ASN.1 blob with the regex \x00\x01[^\x00]*\x00(.*)
print("[*] Forging signature for a validator that checks prefix/suffix...")
# First, our previous forged signature would fail, since it has leftover data
# from ASN.1 parsing (i.e. not right-aligned):
print("    Check that our previous signature would fail here:")
assert not validate_prefix_suffix(r, b"hi mom", forged_signature, bits=3072)
# See comment later for why we're crafting a slightly different message.
target_hash = hashlib.sha1(b"hi mom\x00\x00").digest()
target_suffix = b"\x00" + pkcs1_v1_5.sha1_digest_info(target_hash).encode()
# We can generate the suffix by solving 'suffix = x^3 (mod 2^bitlen(suffix))'.
print("    Crafting suffix...")
xs = roots.solve_pow_with_suffix(target_suffix, n=3)
# Note: turns out "hi mom" doesn't work here (no 'x' possible). This is why we
# are crafting a signature for a slightly different message, which in practice
# would have a similar effect.
assert xs, "No 'x' s.t. x^3 ends with %s. Choose another msg!" % target_suffix
suffix = min(xs)
assert (suffix**3).to_bytes(3072//8, "big").endswith(target_suffix)
suffix_bytes = byteops.int_to_bytes(suffix)

# We can generate a target prefix via integer cube-root.
target_prefix = b"\x00\x01\xff"
total_len = 3072//8
padding_len = total_len - len(target_prefix) - len(target_suffix)
prefix_bytes = _forge_cubed_prefix(target_prefix, total_len, padding_len,
                                   suffix_bytes, forbidden_padding_byte=b"\x00")

print("    Forging final signature...")
forged = prefix_bytes[:-len(suffix_bytes)] + suffix_bytes
print("    Signature: %s" % forged.hex())
forged = int.from_bytes(forged, "big")
print("    Produces:  %s" % (forged**3).to_bytes(3072//8, "big").hex())
assert (forged**3).to_bytes(3072//8, "big").startswith(b"\x00\x01\xff")
assert (forged**3).to_bytes(3072//8, "big").endswith(target_suffix)
assert validate_prefix_suffix(r, b"hi mom\x00\x00", forged, bits=3072)
