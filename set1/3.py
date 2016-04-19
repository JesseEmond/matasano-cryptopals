from xor import xor

cipher = bytes.fromhex(
    '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
)


def decrypt(key):
    return xor(cipher, bytes([key] * len(cipher))).decode('ascii')


def english_test(key):
    english_freq_order = 'etaoinshrdlu'
    try:
        msg = decrypt(key)
    except:
        return 0
    msg = msg.lower()
    frequency = list(set(sorted(msg, key=msg.count, reverse=True)))
    return sum([1 if f in english_freq_order else 0 for f in frequency])

keys = sorted(range(256), key=english_test, reverse=True)
print(decrypt(keys[0]))
