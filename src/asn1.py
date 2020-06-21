# See https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
# Note, we only support (a subset of) DER in this file.

from . import byteops


# Set at the end of this file.
_TAG_TO_TYPE = {}


def tag_to_type(tag):
    return _TAG_TO_TYPE[tag]


def tag_for_instance(instance):
    return next(tag for tag, tag_type in _TAG_TO_TYPE.items()
                if isinstance(instance, tag_type))


def encode_len(len_):
    if len_ < 128: return bytes([len_])
    encoded_len = byteops.int_to_bytes(len_)
    assert len(encoded_len) < 128
    return bytes([0x80 | encoded_len] + encoded_len)


def consume(bytes_, len_):
    return bytes_[:len_], bytes_[len_:]


def decode_len(bytes_):
    """Returns (len, rest)"""
    assert len(bytes_) > 0
    len_, bytes_ = consume(bytes_, 1)
    len_ = len_[0]
    if len_ < 128:
        return len_, bytes_
    len_len = len_ & 0x7F
    assert len(bytes_) >= len_len
    len_bytes, bytes_ = consume(bytes_, len_len)
    decoded_len = int.from_bytes(len_bytes, "big")
    return decoded_len, bytes_


def partial_decode(bytes_):
    """Returns (Asn1Type instance, rest)"""
    assert len(bytes_) >= 2
    tag, bytes_ = consume(bytes_, 1)
    tag = tag[0]
    type_ = tag_to_type(tag)
    len_, bytes_ = decode_len(bytes_)
    value, bytes_ = consume(bytes_, len_)
    return type_.decode(value), bytes_


def decode(bytes_):
    """Returns Asn1Type instance, decoded from the given bytes."""
    instance, _ = partial_decode(bytes_)  # Ignore leftover bytes
    return instance


class Asn1Type:
    """Generic ASN.1 type interface."""

    def encode(self, value):
        tag = tag_for_instance(self)
        len_ = encode_len(len(value))
        return bytes([tag]) + len_ + value

    def decode(value):
        """Returns instance, created from the encoded 'value' bytes."""
        raise NotImplementedError()


class Null(Asn1Type):

    def encode(self):
        return super().encode(b"")

    def decode(bytes_):
        assert len(bytes_) == 0
        return Null()


class ObjectIdentifier(Asn1Type):

    def __init__(self, oid):
        """oid is a list of integers, or string of the form '1.2.3'"""
        # See https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/#object-identifier-encoding
        # for specifics.
        if isinstance(oid, str): oid = list(int(n) for n in oid.split('.'))
        assert len(oid) >= 2
        assert oid[0] in [0, 1, 2]
        assert oid[0] == 2 or oid[1] < 40
        self.oid = oid

    def _encode_component(n):
        bits = bin(n)[2:]
        missing_bits = (-len(bits)) % 7
        bits = bits.rjust(len(bits) + missing_bits, "0")
        assert len(bits) % 7 == 0
        encoded = [int(bits[i:i+7], 2) for i in range(0, len(bits), 7)]
        # Set 8th bit to 1 for every byte except the last in the component.
        encoded = [encoded[i] | 0x80 if i + 1 < len(encoded) else encoded[i]
                   for i in range(len(encoded))]
        return bytes(encoded)

    def _decode_component(component_bytes):
        assert all(byte >= 0x80 for byte in component_bytes[:-1])
        assert component_bytes[-1] < 0x80
        bytes_ = [byte & 0x7F for byte in component_bytes]
        byte_bits = [bin(byte)[2:].rjust(7, "0") for byte in bytes_]
        return int("".join(byte_bits), 2)

    def encode(self):
        oid = [40 * self.oid[0] + self.oid[1]] + self.oid[2:]
        value = b"".join(ObjectIdentifier._encode_component(n) for n in oid)
        return super().encode(value)

    def decode(value):
        oid = []
        while value:
            last_idx = next(idx for idx, byte in enumerate(value)
                            if byte < 0x80)
            component, value = consume(value, last_idx + 1)
            oid.append(ObjectIdentifier._decode_component(component))
        # If x = 0 or 1, then y < 40.
        # oid[0] is 40x + y, so x = 0 => oid[0] < 40. x = 1 => oid[0] < 80
        if oid[0] < 40: x = 0
        elif oid[0] < 80: x = 1
        else: x = 2
        y = oid[0] - 40 * x
        oid = [x, y] + oid[1:]
        return ObjectIdentifier(oid)


class OctetString(Asn1Type):

    def __init__(self, bytes_):
        self.str = bytes_

    def encode(self):
        return super().encode(self.str)

    def decode(value):
        return OctetString(value)


class Sequence(Asn1Type):

    def __init__(self, types):
        self.types = types

    def encode(self):
        value = b"".join(type_.encode() for type_ in self.types)
        return super().encode(value)

    def decode(value):
        types = []
        while value:
            type_, value = partial_decode(value)
            types.append(type_)
        return Sequence(types)


# List of available types, used in encoding/decoding.
_TAG_TO_TYPE = {
        0x04: OctetString,
        0x05: Null,
        0x06: ObjectIdentifier,
        # Sequence will always be in constructed form.
        0x30: Sequence,
}


# encode
assert (OctetString(bytes.fromhex("030206A0")).encode() ==
        bytes.fromhex("0404030206A0"))
assert (ObjectIdentifier("1.2.840.113549.1.1.11").encode() ==
        bytes.fromhex("06092a864886f70d01010b"))
assert (ObjectIdentifier("2.16.840.1.101.3.4.2.1").encode() ==
        bytes.fromhex("0609608648016503040201"))

# decode
# OCTET-STRING
assert (decode(bytes.fromhex("0404030206A0")).encode() == 
        bytes.fromhex("0404030206A0"))
# OID
assert (decode(bytes.fromhex("06092a864886f70d01010b")).encode() ==
        bytes.fromhex("06092a864886f70d01010b"))
# SEQUENCE (sha256 DigestInfo)
assert (decode(
    bytes.fromhex(
        "3031300d060960864801650304020105000420" + "42" * 0x20)).encode() ==
    bytes.fromhex("3031300d060960864801650304020105000420" + "42" * 0x20))
