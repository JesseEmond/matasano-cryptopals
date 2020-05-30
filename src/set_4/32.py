# Very similar to 31, so copied most of the challenge code from it.
# Able to go to 0.1ms wait! Attacking this in practice seems... hard.
from os import urandom

from .. import mac
from .. import timing_attack


class Challenge():

    def __init__(self):
        self._secret = urandom(16)

    def upload(self, file, signature, known_bytes=None):
        """Imagine this is an HTTP GET..."""
        hmac = mac.hmac_sha1(self._secret, file)
        if not timing_attack.insecure_compare(
            hmac, signature, delay_ms=0.1, known_bytes=known_bytes):
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
    bytes([0] * 20), try_hmac, per_byte_rounds=20, progress_callback=on_byte_found)
    

assert challenge.upload(file, hmac) == 200