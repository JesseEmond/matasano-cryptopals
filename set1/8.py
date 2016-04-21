def get_blocks(ciphertext):
    return [ciphertext[idx:idx + 16] for idx in range(0, len(ciphertext), 16)]


with open('8.txt') as f:
    ciphertexts = [bytes.fromhex(line.strip()) for line in f.readlines()]

ciphertexts_blocks = [get_blocks(ciphertext) for ciphertext in ciphertexts]
uniques = [len(set(block)) for block in ciphertexts_blocks]
least_unique_idx = uniques.index(min(uniques))
ecb_encrypted = ciphertexts[least_unique_idx]
print("ECB: %s" % ecb_encrypted)
print("%i unique blocks out of %i" %
      (uniques[least_unique_idx], len(ciphertexts[least_unique_idx])/16))
