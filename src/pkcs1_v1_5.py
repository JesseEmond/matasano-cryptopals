# https://tools.ietf.org/html/rfc3447

from Crypto.Hash import SHA256
import hashlib

from . import asn1


def make_digest_info(algo_oid, digest):
    digest_algo = asn1.Sequence([
        asn1.ObjectIdentifier(algo_oid),
        asn1.Null()])
    return asn1.Sequence([digest_algo, asn1.OctetString(digest)])


def encode(digest_info, total_len):
    digest_info = digest_info.encode()
    padding_len = total_len - 3 - len(digest_info)
    return bytes([0x00, 0x01] + [0xFF] * padding_len + [0x00]) + digest_info


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
    # Generated with:
    # PKCS1_v1_5.pkcs1_15._EMSA_PKCS1_V1_5_ENCODE(SHA256.new(b"hello"), 1024)
    # Using a constant here since this uses a non-public method.
    expected = (b"\x00\x01" + b"\xff" * 970 +
                b"\x00010\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\x04 ,\xf2"
                b"M\xba_\xb0\xa3\x0e&\xe8;*\xc5\xb9\xe2\x9e\x1b\x16\x1e\\\x1f"
                b"\xa7B^s\x043b\x93\x8b\x98$")
    encoded = encode(sha256_digest_info(hashlib.sha256(b"hello").digest()),
                     1024)
    assert encoded == expected
