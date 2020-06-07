import hmac as py_hmac
import hashlib

from . import md4
from . import sha1
from . import xor


def keyed_mac(key, message, hash_fn):
    return hash_fn(key + message)


def hmac(key, message, hash_class):
    if len(key) < hash_class.BLOCK_SIZE:
        key = key.ljust(hash_class.BLOCK_SIZE, b"\x00")
    elif len(key) > hash_class.BLOCK_SIZE:
        key = hash_class().update(key).digest()
    outer_key = xor.xor_single_char_key(key, 0x5c)
    inner_key = xor.xor_single_char_key(key, 0x36)
    hash_fn = lambda data: hash_class().update(data).digest()
    inner = keyed_mac(inner_key, message, hash_fn)
    return keyed_mac(outer_key, inner, hash_fn)


def sha1_keyed_mac(key, message):
    return keyed_mac(key, message, sha1.sha1)


def md4_keyed_mac(key, message):
    return keyed_mac(key, message, md4.md4)


def hmac_sha1(key, message):
    return hmac(key, message, sha1.Sha1)
assert(hmac_sha1(b"key", b"The quick brown fox jumps over the lazy dog") ==
    bytes.fromhex("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"))


def hmac_sha256(key, message):
    return py_hmac.new(key, message, hashlib.sha256).digest()
