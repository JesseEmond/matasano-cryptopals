from .. import aes
from .. import merkle_damgard


class CheapHash(merkle_damgard.Hash):
    BLOCK_SIZE = 2  # 16 bits
    STATE_ENTRY_SIZE = 2
    STATE_ENTRIES = 1

    def __init__(self, h=None, msg_len=0):
        h = h or (0x1337,)
        super().__init__(h, msg_len)

    @classmethod
    def process_chunk(cls, chunk, state):
        assert len(chunk) == 2
        h = state[0]
        block = b"\x00" * 14 + chunk
        key = h.to_bytes(16, "big")
        out = aes.aes_encrypt_block(key, block)
        h = int.from_bytes(out[:2], "big")
        return (h,)


def final_state(msg):
    return CheapHash().update(msg).state()


# Testing our expandable messages logic.
expandable = merkle_damgard.ExpandableMessages(CheapHash, k=4, verbose=True)
# With this, can generate messages in [4, 4+2**4-1] = [4, 19].
short_msg = expandable.expand_to(4)
print(f"For k=4  message: {short_msg}  state: {final_state(short_msg)}")
for n in range(4, 19+1):
    msg = expandable.expand_to(n)
    print(f"Checking n={n}... msg: {msg}  state: {final_state(msg)}")
    assert final_state(msg) == final_state(short_msg)

# Generating a 2nd preimage collision.
msg = b"Hello world this is a test...!?!HELLO WORLD THIS IS A TEST,,,;;;"
assert len(msg) == 2**5 * CheapHash.BLOCK_SIZE
collision = CheapHash.second_preimage_collision(msg, verbose=True)
print(f"msg: {msg}  H(msg): {CheapHash().update(msg).digest().hex()}")
print(f"msg': {collision}  H(msg'): "
      f"{CheapHash().update(collision).digest().hex()}")
assert (CheapHash().update(msg).digest() ==
        CheapHash().update(collision).digest())
