from os import urandom
from string import printable

from aes import cbc_encrypt, cbc_decrypt, get_blocks
from xor import xor_bytes


KEY = urandom(16)
IV = KEY


def escape(s):
    return s.replace("%", "%37").replace("=", "%61").replace(";", "%59")


def get_token(userdata):
    cookie = escape(userdata)
    return cbc_encrypt(KEY, IV, cookie.encode('latin-1'))


class InvalidAsciiError(Exception):
    def __init__(self, message):
        self.message = message


def oracle(token):
    cookie = cbc_decrypt(KEY, IV, token)

    if not all(chr(c) in printable for c in cookie):
        raise InvalidAsciiError(b"'%s' is not ASCII!" % cookie)


# escape tests
assert("%61" == escape("="))
assert("%59" == escape(";"))
assert("%37" == escape("%"))
assert("a%61b" == escape("a=b"))
assert("a%3761b" == escape("a%61b"))

# oracle tests
try:
    oracle(get_token("test"))
except:
    assert(False)
try:
    not oracle(get_token("test\x00"))
    assert(False)
except: pass


secret = "lorem=ipsum;test=fun;padding=dull"
ciphertext = get_token(secret)
c_1, c_2, c_3 = get_blocks(ciphertext)

# We might be unlucky and not get an invalid ASCII character.
# If this happens, add a suffix (which will generate new seemingly random data)
# until it works.
suffix = bytearray()
suffix.extend(c_2 + c_3)  # manage to get valid padding

for _ in range(10):  # try a couple of times
    try:
        plaintext = oracle(c_1 + bytes([0] * 16) + c_1 + suffix)
    except InvalidAsciiError as e:
        plaintext = e.message[1:-15]
        p_1, _, p_3 = get_blocks(plaintext)[0:3]
    
        # p_1 is p_3 ^ K
        key = xor_bytes(p_1, p_3)
        assert(key == KEY)
        exit()

    print("No lowercase ASCII! Adding blocks...")
    suffix.extend(urandom(16) + c_2 + c_3)

assert(False)
