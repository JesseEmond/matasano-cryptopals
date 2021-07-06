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


class LessCheapHash(merkle_damgard.Hash):
    BLOCK_SIZE = 4  # 32 bits
    STATE_ENTRY_SIZE = 2
    STATE_ENTRIES = 2

    def __init__(self, h=None, msg_len=0):
        h = h or (0x4242, 0x9001)
        super().__init__(h, msg_len)

    @classmethod
    def process_chunk(cls, chunk, state):
        assert len(chunk) == 4
        h1, h2 = state
        block = b"\x00" * 12 + chunk
        key = h1.to_bytes(2, "big") + b"\x00" * 12 + h2.to_bytes(2, "big")
        out = aes.aes_encrypt_block(key, block)
        h1 = int.from_bytes(out[:2], "big")
        h2 = int.from_bytes(out[2:4], "big")
        return (h1, h2)


def verify_collisions(collisions, hash_cls):
    ref_digest = hash_cls().update(collisions[0]).digest()
    for c in collisions:
        digest = hash_cls().update(c).digest()
        assert digest == ref_digest
        print(f"f({c}) = {digest.hex()}")


def f(x):
    return CheapHash().update(x).digest()


def g(x):
    return LessCheapHash().update(x).digest()


def h(x):
    return f(x) + g(x)


if __name__ == "__main__":
    print(f"f(hi) = {f(b'hi').hex()}")
    print(f"f(hello) = {f(b'hello').hex()}")

    print("Generating 2 collisions...")
    collisions = list(CheapHash.generate_multicollisions(n=1, verbose=True))
    assert len(collisions) == 2
    verify_collisions(collisions, CheapHash)

    print("Generating 8 collisions...")
    collisions = list(CheapHash.generate_multicollisions(n=3, verbose=True))
    assert len(collisions) == 8
    verify_collisions(collisions, CheapHash)

    b1, b2 = CheapHash.state_size() * 8, LessCheapHash.state_size() * 8
    print(f"b1={b1}  b2={b2}")
    print(f"Generating 2**{b2//2} f collisions...")
    f_generator = merkle_damgard.MulticollisionGenerator(CheapHash)
    for i in range(b2//2):
        f_generator.next()
        print(f"  .. {i+1}/{b2//2}")
    print("Searching for a g collision...")
    num_g_calls = 0
    done = False
    while not done:
        g_hash_to_block = {}
        for x in f_generator.all_collisions():
            num_g_calls += 1
            g_hash = g(x)
            if g_hash in g_hash_to_block and x != g_hash_to_block[g_hash]:
                y = g_hash_to_block[g_hash]
                print("g collision found!")
                print(f"g({x}) = {g(x).hex()}   g({y}) = {g(y).hex()}")
                done = True
                break
            g_hash_to_block[g_hash] = x
        if not done:
            print(f"No collision found with "
                  f"{f_generator.num_collisions()} f collisions.")
            f_generator.next()
            print(f"Trying again with "
                  f"{f_generator.num_collisions()} f collisions.")
    print(f"f({x}) = {f(x).hex()}   f({y}) = {f(y).hex()}")
    print(f"g({x}) = {g(x).hex()}   g({y}) = {g(y).hex()}")
    print(f"h({x}) = {h(x).hex()}   h({y}) = {h(y).hex()}")
    print(f"f calls: {f_generator.num_calls}  g calls: {num_g_calls}")
    assert f(x) == f(y)
    assert g(x) == g(y)
    assert h(x) == h(y)
