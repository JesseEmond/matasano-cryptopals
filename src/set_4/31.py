import statistics
import time
from os import urandom

from .. import mac


def insecure_compare(a, b, delay_ms=2, known_bytes=0):
    # Picking a lower delay, because this takes a while to run. :)
    # Note that 'known_bytes' is cheating. But this needs to run on
    # travis in a reasonable time, so only add the delay for unknown
    # bytes.
    if len(a) != len(b): return False
    known_bytes = known_bytes or 0
    for i, (aa, bb) in enumerate(zip(a, b)):
        if aa != bb: return False
        if i >= known_bytes: time.sleep(delay_ms / 1000)
    return True


class Challenge():

    def __init__(self):
        self._secret = urandom(16)

    def upload(self, file, signature, known_bytes=None):
        """Imagine this is an HTTP GET..."""
        hmac = mac.hmac_sha1(self._secret, file)
        if not insecure_compare(hmac, signature,
                                known_bytes=known_bytes):
            return 500
        print("Successful upload of %s.", file)
        return 200

    def _peek(self, file):
        """Only used to provide debug info in print."""
        hmac = mac.hmac_sha1(self._secret, file)
        print("Psst. You're looking for ", hmac.hex())


def time_attempt(challenge, file, hmac, known_bytes=None):
    start = time.time()
    challenge.upload(file, hmac, known_bytes=known_bytes)
    return time.time() - start


challenge = Challenge()

file = b"evil_payload.exe"
hmac = bytearray([0] * 20)

challenge._peek(file)

rounds = 10  # How many rounds per byte
for i in range(len(hmac)):
    # If this is 'None', we don't "cheat" by skipping delays (extra noise)
    # before the last known byte. Adding this to play nice with Travis.
    known_bytes = i
    byte_times = []
    for b in range(256):
        hmac[i] = b
        times = [time_attempt(challenge, file, hmac, known_bytes)
                 for _ in range(rounds)]
        byte_times.append(times)
    get_byte_time_fn = lambda b: statistics.median(byte_times[b])
    highest_median_byte = max(range(256), key=get_byte_time_fn)
    hmac[i] = highest_median_byte
    print("Byte %d of hmac is %x" % (i, highest_median_byte))
    
assert challenge.upload(file, hmac) == 200