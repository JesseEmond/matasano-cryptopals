from mac import sha1_keyed_mac
from os import urandom


KEY = urandom(16)
# simple test, not much to do here...
assert(sha1_keyed_mac(KEY, b"attack") !=
       sha1_keyed_mac(KEY, b"attack at dawn"))
