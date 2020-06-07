from .. import random_helper
from ..mac import sha1_keyed_mac


KEY = random_helper.random_bytes(16)
# simple test, not much to do here...
assert(sha1_keyed_mac(KEY, b"attack") !=
       sha1_keyed_mac(KEY, b"attack at dawn"))
