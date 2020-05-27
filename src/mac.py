from sha1 import sha1


def keyed_mac(key, message, hash_):
    return hash_(key + message)


def sha1_keyed_mac(key, message):
    return keyed_mac(key, message, sha1)