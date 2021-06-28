import string
import zlib

from .. import aes
from .. import random_helper


def encrypt_stream_cipher(plaintext):
    key = random_helper.random_bytes(16)
    nonce = random_helper.random_number(bits=64)
    nonce_bytes = nonce.to_bytes(8, "big")
    return nonce_bytes + aes.ctr_encrypt(key, nonce, plaintext)


def encrypt_block_cipher(plaintext):
    iv = random_helper.random_bytes(16)
    key = random_helper.random_bytes(16)
    return iv + aes.cbc_encrypt(key, iv, plaintext)


def compress(text):
    return zlib.compress(text)


def format_request(data):
    data = data.decode("ascii")
    return f"""POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: {len(data)}
{data}""".encode("ascii")


def compression_oracle(data, encrypt_fn):
    return len(encrypt_fn(compress(format_request(data))))


def next_char_candidates(oracle_fn, prefix, alphabet):
    letters_lens = {letter: oracle_fn(prefix + letter.encode("ascii"))
                    for letter in alphabet}
    best_len = min(letters_lens.values())
    candidates = [letter for letter, len_ in letters_lens.items()
                  if len_ == best_len]
    return candidates, best_len


def narrow_candidates(candidates, oracle_fn, prefix, alphabet):
    next_candidates = {
        letter: next_char_candidates(oracle_fn,
                                     prefix + letter.encode("ascii"),
                                     alphabet)
        for letter in candidates}
    best_len = min(oracle_len
                   for _, (_, oracle_len) in next_candidates.items())
    best_letters = [letter
                    for letter, (_, oracle_len) in next_candidates.items()
                    if oracle_len == best_len]
    return best_letters


def decrypt_compression(oracle_fn, known_prefix, done_fn,
                        alphabet=string.printable, verbose=False,
                        block_based=False):
    if verbose:
        print("Decrypted: ", end="", flush=True)
    decrypted = bytearray()
    padding = b""
    while not done_fn(decrypted):
        prefix = padding + known_prefix + decrypted
        candidates, _ = next_char_candidates(oracle_fn, prefix, alphabet)
        if len(candidates) > 1:  # Narrow down by trying each one.
            candidates = narrow_candidates(candidates, oracle_fn,
                                           prefix, alphabet)
            if len(candidates) > 1:
                if block_based:
                    # Perhaps we are not at a block boundary. Try again, but
                    # with padding to push us closer to a block boundary.
                    rand_byte = random_helper.random_number(below=128)
                    padding += bytes([rand_byte])
                    continue
                else:
                    # Should not happen. Our oracle doesn't hold our
                    # assumptions, perhaps.
                    assert len(candidates) == 1, candidates
        decrypted.append(ord(candidates[0]))
        if verbose:
            print(chr(decrypted[-1]), end="", flush=True)
    if verbose:
        print()
    return bytes(decrypted)


def ends_in_newline(text):
    """Used to know when we're done with decryption."""
    return text.endswith(b"\n")


def compression_oracle_stream(data):
    return compression_oracle(data, encrypt_stream_cipher)


def compression_oracle_block(data):
    return compression_oracle(data, encrypt_block_cipher)


print("With stream cipher:")
recovered = decrypt_compression(compression_oracle_stream,
                                known_prefix=b"sessionid=",
                                done_fn=ends_in_newline, verbose=True)
assert recovered[:-1] == b"TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="

print("With block cipher:")
recovered = decrypt_compression(compression_oracle_block,
                                known_prefix=b"sessionid=",
                                done_fn=ends_in_newline, block_based=True,
                                verbose=True)
assert recovered[:-1] == b"TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
