from .. import mac
from .. import random_helper
from .. import timing_attack


class Challenge():

    def __init__(self):
        self._secret = random_helper.random_bytes(16)

    def upload(self, file, signature, known_bytes=None):
        """Imagine this is an HTTP GET..."""
        hmac = mac.hmac_sha1(self._secret, file)
        if not timing_attack.insecure_compare(
            hmac, signature, delay_ms=2, known_bytes=known_bytes):
            return 500
        print("Successful upload of %s.", file)
        return 200

    def _peek(self, file):
        """Only used to provide debug info in print."""
        hmac = mac.hmac_sha1(self._secret, file)
        print("Psst. You're looking for ", hmac.hex())




challenge = Challenge()

file = b"evil_payload.exe"

challenge._peek(file)

# If this is 'None', we don't "cheat" by skipping delays (extra noise)
# before the last known byte. Adding this to play nice with Travis.
known_bytes = 0


def try_hmac(hmac):
    challenge.upload(file, hmac, known_bytes)


def on_byte_found(hmac, byte_idx):
    global known_bytes
    known_bytes = byte_idx + 1
    print("Byte %d of hmac is %x" % (byte_idx, hmac[byte_idx]))


hmac = timing_attack.comparison_time_attack(
    bytes([0] * 20), try_hmac, per_byte_rounds=10, progress_callback=on_byte_found)
    

assert challenge.upload(file, hmac) == 200
