from ..aes import get_blocks


with open('src/set_1/08.txt') as f:
    ciphertexts = [bytes.fromhex(line.strip()) for line in f.readlines()]

ciphertexts_blocks = [get_blocks(ciphertext) for ciphertext in ciphertexts]
uniques = [len(set(block)) for block in ciphertexts_blocks]
least_unique_idx = uniques.index(min(uniques))
ecb_encrypted = ciphertexts[least_unique_idx]
print("ECB: %s" % ecb_encrypted)
print("%i unique blocks out of %i" %
      (uniques[least_unique_idx], len(ciphertexts[least_unique_idx])/16))

assert(ecb_encrypted.startswith(
       b'\xd8\x80a\x97@\xa8\xa1\x9bx@\xa8\xa3\x1c\x81\n=\x08d\x9a\xf7'))
