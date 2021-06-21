# https://tools.ietf.org/html/rfc3447

import hashlib
import os

from . import asn1


def make_digest_info(algo_oid, digest):
    digest_algo = asn1.Sequence([
        asn1.ObjectIdentifier(algo_oid),
        asn1.Null()])
    return asn1.Sequence([digest_algo, asn1.OctetString(digest)])


def signing_pad(digest_info, total_len):
    digest_info = digest_info.encode()
    padding_len = total_len - 3 - len(digest_info)
    return bytes([0x00, 0x01] + [0xFF] * padding_len + [0x00]) + digest_info


def encrypt_pad(data, total_len):
    pad_size = total_len - len(data) - 3
    assert pad_size >= 8
    pad = b""
    while len(pad) < pad_size:
        byte = os.urandom(1)
        if byte != b"\x00":
            pad += byte
    return b"\x00\x02" + pad + b"\x00" + data


def encrypt_unpad(padded, total_len):
    """Returns the padded data. Raises ValueError for invalid padding."""
    padded = padded.rjust(total_len, b"\x00")
    if not padded.startswith(b"\x00\x02"):
        raise ValueError()
    index = padded.index(b"\x00", 2)  # Raises ValueError if missing.
    if index < 2 + 8:  # Min 8 bytes of padding.
        raise ValueError()
    return padded[index+1:]


def sha256_digest_info(digest):
    """See https://tools.ietf.org/html/rfc3447#section-9.2"""
    # http://oid-info.com/get/2.16.840.1.101.3.4.2.1
    return make_digest_info("2.16.840.1.101.3.4.2.1", digest)


def sha1_digest_info(digest):
    # http://oid-info.com/get/1.3.14.3.2.26
    return make_digest_info("1.3.14.3.2.26", digest)


def get_digest(digest_asn1, ensure_full_parse=False):
    """Call this on an extracted ASN.1-encoded digest."""
    digest_info, leftover = asn1.partial_decode(digest_asn1)
    if ensure_full_parse and len(leftover) > 0:
        return None
    return digest_info.types[1].str


if __name__ == "__main__":
    # Padding for signing.
    # Generated with:
    # PKCS1_v1_5.pkcs1_15._EMSA_PKCS1_V1_5_ENCODE(SHA256.new(b"hello"), 1024)
    # Using a constant here since this uses a non-public method.
    expected = (b"\x00\x01" + b"\xff" * 970 +
                b"\x00010\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\x04 ,\xf2"
                b"M\xba_\xb0\xa3\x0e&\xe8;*\xc5\xb9\xe2\x9e\x1b\x16\x1e\\\x1f"
                b"\xa7B^s\x043b\x93\x8b\x98$")
    padded = signing_pad(sha256_digest_info(hashlib.sha256(b"hello").digest()),
                         1024)
    assert padded == expected

    # Padding for encrypting.
    data = b"helloworld"
    padded = encrypt_pad(data, 64)
    print(padded)
    assert len(padded) == 64
    assert encrypt_unpad(padded, 64) == b"helloworld"

    def should_fail(data, total_len):
        try:
            encrypt_unpad(data, total_len)
            assert False, data
        except ValueError:
            pass

    should_fail(b"test", 4)
    should_fail(b"\x00test", 5)
    should_fail(b"\x02AAAABBBBtest", 13)
    should_fail(b"\x00\x02AAAA\x00test", 11)
    should_fail(b"\x00\x02AAAABBBBtest", 14)
    assert encrypt_unpad(b"\x00\x02AAAABBBB\x00test", 15) == b"test"
    assert encrypt_unpad(b"\x02AAAABBBB\x00test", 15) == b"test"
