from .. import ints
from .. import mod
from .. import rsa


# The secret message that we want to recover.
PRIVATE_MESSAGE = int.from_bytes(b"Hello this is a secret message.", "big")


def add_padding(m, modulus_bits, padding_len):
    padding_bits = padding_len * 8
    padding = (1 << padding_bits) - 1  # [0xFF] * padding_len
    # Note: we keep first byte as 0x00 to ensure < modulus
    assert modulus_bits > 8 + padding_bits
    padding <<= modulus_bits - 8 - padding_bits
    assert m < padding
    return padding | m
assert add_padding(0x42, modulus_bits=4*8, padding_len=2) == 0x00FFFF42


def remove_padding(padded_m, padding_len):
    padding_bits = padding_len * 8
    assert padded_m.bit_length() > padding_bits
    m_bits = padded_m.bit_length() - padding_bits
    mask = (1 << m_bits) - 1
    return padded_m & mask
assert remove_padding(add_padding(0x42, modulus_bits=4*8, padding_len=2),
                      padding_len=2) == 0x42


def capture_messages(e, bits=1024, padding_fn=None):
    """Returns a list of 'e' (ciphertext, mudolus) pairs."""
    m = PRIVATE_MESSAGE
    parties = [rsa.Rsa(e=e, bits=bits) for _ in range(e)]
    m = padding_fn(m) if padding_fn is not None else m
    return [(r.encrypt(m), r.n) for r in parties]


# First of all, if p is small, we can directly recover it (it doesn't ever wrap
# around N):
print("[*] Recovering m^3 for small m.")
print("      gen keys & encrypt...")
c = rsa.Rsa(e=3, bits=1024).encrypt(PRIVATE_MESSAGE)
print("      cube root...")
assert ints.iroot(c, 3) == PRIVATE_MESSAGE
print("      recovered!")

# If we add some static "padding" at the start, causing p^3 to wrap, we can
# still recover p through CRT.
print("[*] Recovering m^3 for larger m, that wraps around N.")
static_pad = lambda m: add_padding(m, modulus_bits=1024, padding_len=3)
print("      capturing 3 ciphertexts...")
((c_0, n_0), (c_1, n_1), (c_2, n_2)) = capture_messages(e=3, bits=1024,
                                                        padding_fn=static_pad)
print("      checking that cube root isn't sufficient...")
assert remove_padding(ints.iroot(c_0, 3), padding_len=3) != PRIVATE_MESSAGE
print("      crt...")
c = mod.crt(residues=[c_0, c_1, c_2], moduli=[n_0, n_1, n_2])
print("      cube root...")
p = ints.iroot(c, 3)
assert remove_padding(p, padding_len=3) == PRIVATE_MESSAGE
print("      recovered!")
