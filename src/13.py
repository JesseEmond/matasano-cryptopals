from aes import ecb_encrypt, ecb_decrypt
from os import urandom


key = urandom(16)


def sanitize(s):
    return s.replace('&', '').replace('=', '')


def profile_for(email):
    profile = [('email', email), ('uid', '10'), ('role', 'user')]

    encoded = [k + '=' + sanitize(v) for k, v in profile]
    return '&'.join(encoded)


def parse_profile(encoded):
    fields = encoded.split('&')
    items = [tuple(field.split('=')) for field in fields]
    profile = {key: value for key, value in items}
    return profile


def oracle(email):
    return ecb_encrypt(key, profile_for(email).encode('ascii'))


def log_in(token):
    decrypted = ecb_decrypt(key, token)

    profile = parse_profile(decrypted.decode('ascii'))
    return profile['role'] == 'admin'


# sanitize tests
assert('a@b.c' == sanitize('a@b.c'))
assert('ab' == sanitize('a&b'))
assert('ab' == sanitize('a=b'))
assert('roleadminemailc' == sanitize('role=admin&email=c'))

# profile_for tests
assert('email=foo@bar.com&uid=10&role=user' == profile_for('foo@bar.com'))

# parse_profile tests
assert('user' == parse_profile('email=foo@bar.com&uid=10&role=user')['role'])

# login test
assert(not log_in(oracle('a')))


# we want to produce the following blocks:
# email=aaaaaaaaaa
# aaa&uid=10&role=
# adminPPPPPPPPPPP (padding)

# craft an admin block (with padding): (P is padding, | is our target)
# email=aaaaaaaaaaadminPPPPPPPPPPP&uid=10&role=userPPPPPPPPPPPPPPP
# ................||||||||||||||||................................
admin_encrypted = oracle('aaaaaaaaaaadmin' + '\x0b' * 11)
assert(len(admin_encrypted) == 4 * 16)
admin_block = admin_encrypted[16:32]

normal_blocks = oracle('aaaaaaaaaaaaa')
assert(len(normal_blocks) == 3 * 16)

crafted = normal_blocks[:32] + admin_block

logged = log_in(crafted)
print("Logged: %s" % str(logged))
assert(logged)
