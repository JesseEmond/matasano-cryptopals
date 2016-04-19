def english_test(bytes_):
    english_freq_order = 'etaoinshrdlu'

    try:
        msg = bytes_.decode('ascii')
    except:
        return 0

    msg = msg.lower()

    freq = list(set(sorted(msg, key=msg.count, reverse=True)))
    return sum([1 if f in english_freq_order else 0 for f in freq])
