from .. import aes
from .. import mac
from .. import xor


KEY = b"YELLOW SUBMARINE"


def cbc_mac_hash(m):
    return mac.cbc_mac(KEY, m)


assert (cbc_mac_hash(b"alert('MZA who was that?');\n") ==
        bytes.fromhex("296b8d7cb78a243dda4d0a61d33bbdd1"))
target_hash = bytes.fromhex("296b8d7cb78a243dda4d0a61d33bbdd1")
target_pre = aes.aes_decrypt_block(KEY, target_hash)

crafted = b"alert('Ayo, the Wu is back!');/*"
crafted += b"A" * (-len(crafted) % 16)  # Pad to block size for convenience.
assert len(crafted) % 16 == 0

# Figure out what our iv will be at that point:
iv = b"\x00" * 16
for block in aes.get_blocks(crafted):
    block = xor.xor_bytes(iv, block)
    iv = aes.aes_encrypt_block(KEY, block)

# Our last block will look like:
# ...*/\x01  (\x01 for padding)
ending = b"BBBBBBBBBBBBB*/"  # Leave one space after for \x01
assert len(ending) == 15
ending_padded = ending + b"\x01"

# Craft our middle block to give our target_pre.
middle_encrypted = xor.xor_bytes(ending_padded, target_pre)
middle = aes.aes_decrypt_block(KEY, middle_encrypted)
middle = xor.xor_bytes(iv, middle)

crafted += middle + ending
assert cbc_mac_hash(crafted) == target_hash
print(crafted)
