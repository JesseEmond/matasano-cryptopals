import statistics
import time


def time_fn(fn):
    start = time.time()
    fn()
    return time.time() - start


def comparison_time_attack(data, try_data_fn, per_byte_rounds,
    progress_callback=None):
    """Attack a comparison that early-exits when there's a mismatch."""
    data = bytearray(data)
    for i in range(len(data)):
        byte_times = []
        for b in range(256):
            data[i] = b
            times = [time_fn(lambda: try_data_fn(data))
                     for _ in range(per_byte_rounds)]
            byte_times.append(times)
        get_byte_time_fn = lambda b: statistics.median(byte_times[b])
        highest_median_byte = max(range(256), key=get_byte_time_fn)
        data[i] = highest_median_byte
        if progress_callback is not None:
            progress_callback(data, i)
    return bytes(data)


def insecure_compare(a, b, delay_ms=2, known_bytes=0):
    # Note that 'known_bytes' is cheating. But this needs to run on
    # travis in a reasonable time, so only add the delay for unknown
    # bytes. If set to 'None', we don't use known_bytes.
    if len(a) != len(b): return False
    known_bytes = known_bytes or 0
    for i, (aa, bb) in enumerate(zip(a, b)):
        if aa != bb: return False
        if i >= known_bytes: time.sleep(delay_ms / 1000)
    return True