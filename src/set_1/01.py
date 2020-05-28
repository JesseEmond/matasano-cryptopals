from ..mybase64 import b64encode


hex_str = ("49276d206b696c6c696e6720796f7572"
           "20627261696e206c696b65206120706f"
           "69736f6e6f7573206d757368726f6f6d")
bytes_ = bytes.fromhex(hex_str)

encoded = b64encode(bytes_)
print(encoded)

expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
assert(encoded == expected)
