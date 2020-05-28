from .. import mac
from .. import sha1


class Challenge:

	def __init__(self):
		self._secret = b"yellowsubmarine"  # Super secret. Do not share.

	def init_cookie(self):
		cookie = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
		cookie_mac = mac.sha1_keyed_mac(self._secret, cookie)
		return cookie, cookie_mac

	def validate(self, cookie, cookie_mac):
		return mac.sha1_keyed_mac(self._secret, cookie) == cookie_mac

	def parse(self, cookie):
		params = cookie.split(b';')
		variables = {}
		for param in params:
			key, value = param.split(b'=', maxsplit=1)
			variables[key] = value.replace(b'%20', b' ')
		return variables

	def get_flag(self, cookie, cookie_mac):
		if not self.validate(cookie, cookie_mac): return False  # Invalid MAC.
		variables = self.parse(cookie)
		return variables.get(b'admin', b'false') == b'true'


challenge = Challenge()
cookie, orig_cookie_mac = challenge.init_cookie()
assert challenge.validate(cookie, orig_cookie_mac)
extra = b";admin=true"

for secret_len in range(32):
	msg_len = secret_len + len(cookie)
	cookie_mac, to_append = sha1.Sha1.length_extension_attack(orig_cookie_mac, msg_len, extra)
	if challenge.validate(cookie + to_append, cookie_mac): break

cookie += to_append
# We should have found the right length. Then these asserts should pass.
assert challenge.validate(cookie, cookie_mac)
assert challenge.get_flag(cookie, cookie_mac)