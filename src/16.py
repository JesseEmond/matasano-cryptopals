from aes import cbc_encrypt, cbc_decrypt
from xor import xor_bytes
from os import urandom


KEY = urandom(16)
IV = urandom(16)


def escape(s):
    return s.replace("%", "%37").replace("=", "%61").replace(";", "%59")


def unescape(s):
    return s.replace("%59", ";").replace("%61", "=").replace("%37", "%")


def get_token(userdata):
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    cookie = prefix + escape(userdata) + suffix
    return cbc_encrypt(KEY, IV, cookie.encode('latin-1'))


def is_admin(token):
    cookie = cbc_decrypt(KEY, IV, token).decode('latin-1')
    fields = cookie.split(';')
    items = [(key, unescape(value)) for key, value in
             (field.split('=') for field in fields)]
    return any([item == ('admin', 'true') for item in items])


# escape tests
assert("%61" == escape("="))
assert("%59" == escape(";"))
assert("%37" == escape("%"))
assert("a%61b" == escape("a=b"))
assert("a%3761b" == escape("a%61b"))

# unescape tests
assert("=" == unescape("%61"))
assert(";" == unescape("%59"))
assert("%" == unescape("%37"))
assert("a=b" == unescape("a%61b"))
assert("a%61b" == unescape("a%3761b"))

# is_admin tests
assert(not is_admin(get_token("a")))
assert(not is_admin(get_token(";admin=true")))


# get a normal token with a filled block, we'll end up with the following:
# (prefix)...      (input)     ...(suffix)
# (32 bytes)  |-----block----| (the rest, not important)
token = get_token("a" * 16)

target = ";admin=true;abc=".encode('ascii')
current_block = token[32:32+16]
next_block_plain = ";comment2=%20lik".encode('ascii')
# decryption does: plaintext = next_block_pre_xor ^ current_block
next_block_pre_xor = xor_bytes(next_block_plain, current_block)

# craft a block with the bitflips that we want to produce on the next block
# we want to craft a current_block so that decryption does:
# target = next_block_pre_xor ^ crafted_block
# so we isolated current_block and get:
crafted_block = xor_bytes(target, next_block_pre_xor)
assert(len(crafted_block) == 16)

crafted_token = token[:32] + crafted_block + token[32+16:]

assert(is_admin(crafted_token))
