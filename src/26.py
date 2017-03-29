from aes import ctr_encrypt, ctr_decrypt
from xor import xor_bytes
from os import urandom


KEY = urandom(16)
NONCE = int.from_bytes(urandom(8), byteorder='big')


def escape(s):
    return s.replace("%", "%37").replace("=", "%61").replace(";", "%59")


def unescape(s):
    return s.replace("%59", ";").replace("%61", "=").replace("%37", "%")


token_prefix = "comment1=cooking%20MCs;userdata="
def get_token(userdata):
    global token_prefix
    prefix = token_prefix
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    cookie = prefix + escape(userdata) + suffix
    return ctr_encrypt(KEY, NONCE, cookie.encode('latin-1'))


def is_admin(token):
    cookie = ctr_decrypt(KEY, NONCE, token).decode('latin-1')
    fields = cookie.split(';')
    items = [(key, unescape(value)) for key, value in
             (field.split('=', maxsplit=1) for field in fields
              if "=" in field)]
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


target = ";admin=true;".encode('ascii')
original = "a" * len(target)
token = get_token(original)

to_modify = token[len(token_prefix):len(token_prefix) + len(original)]
keystream = xor_bytes(to_modify, original.encode('ascii'))

crafted = xor_bytes(keystream, target)
crafted_token = (token[:len(token_prefix)] + crafted +
                 token[len(token_prefix) + len(crafted):])

assert(is_admin(crafted_token))
