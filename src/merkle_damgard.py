import itertools

from . import random_helper


class Hash:
    # The following parameters can be overloaded by children classes
    # if needed.
    BLOCK_SIZE = 64
    ENCODED_LEN_SIZE = 8  # Store length as 64-bits
    ENDIANNESS = "big"
    STATE_ENTRY_SIZE = 4  # Size of each entry in the state, in bytes.
    STATE_ENTRIES = 4

    @classmethod
    def length_padding(cls, msg_len):
        """Produces the padding that should be appended to the message."""
        padding = bytearray()
        # Append bit '1' (0x80 because message is multiple of 8-bits)
        padding.append(0x80)
        # Want final_msg_len % block_size = (block_size - length_size).
        new_len = msg_len + 1  # including the '1' bit added
        target_modulo = cls.BLOCK_SIZE - cls.ENCODED_LEN_SIZE
        missing_len = (target_modulo - new_len) % cls.BLOCK_SIZE
        padding.extend(b"\x00" * missing_len)
        # Append the original length, with the target encoding size.
        msg_len_bits = msg_len * cls.ENCODED_LEN_SIZE
        padding.extend(msg_len_bits.to_bytes(cls.ENCODED_LEN_SIZE,
                                             cls.ENDIANNESS))
        return bytes(padding)

    @classmethod
    def state_size(cls):
        return cls.STATE_ENTRIES * cls.STATE_ENTRY_SIZE

    def __init__(self, iv, msg_len=0):
        assert len(iv) == self.STATE_ENTRIES
        self._state = iv
        self._msg_len = msg_len
        self._unprocessed = bytearray()

    def update(self, data):
        self._msg_len += len(data)
        self._unprocessed.extend(data)
        self._process_unprocessed()
        return self

    def digest(self):
        glue = self.length_padding(self._msg_len)
        self._unprocessed.extend(glue)
        assert len(self._unprocessed) % self.BLOCK_SIZE == 0
        self._process_unprocessed()
        assert len(self._unprocessed) == 0
        return b"".join(h.to_bytes(self.STATE_ENTRY_SIZE, self.ENDIANNESS)
                        for h in self._state)

    @classmethod
    def process_chunk(cls, chunk, state):
        raise NotImplementedError("process_chunk")

    def _process_unprocessed(self):
        while len(self._unprocessed) >= self.BLOCK_SIZE:
            chunk = self._unprocessed[:self.BLOCK_SIZE]
            self._state = self.process_chunk(chunk, self._state)
            assert len(self._state) == self.STATE_ENTRIES
            self._unprocessed = self._unprocessed[self.BLOCK_SIZE:]

    @classmethod
    def length_extension_attack(cls, digest, prev_msg_len, extra):
        """Bootstrap the state from an existing digest, for length-extension attacks.

        Returns:
            (new_digest, to_append)
        """
        state = tuple(int.from_bytes(digest[i:i + 4], cls.ENDIANNESS)
                      for i in range(0, len(digest), 4))
        glue = cls.length_padding(prev_msg_len)
        hash_ = cls(state, prev_msg_len + len(glue))
        return hash_.update(extra).digest(), glue + extra

    @classmethod
    def generate_collisions(cls, n, verbose=False):
        """Yields 2**n collisions."""
        generator = CollisionGenerator(cls)
        for i in range(n):
            generator.next()
            if verbose:
                print(f"  ... found {i+1}/{n} colliding blocks...")
        if verbose:
            print(f"Made {generator.num_calls} hash calls in total.")
        return generator.all_collisions()


class CollisionGenerator:
    """Helper class to iteratively generate more collisions of a MD hash."""
    def __init__(self, hash_cls):
        self.hash_cls = hash_cls
        # Sequential pairs of blocks that give a collision under hash_cls.
        # With n pairs of colliding blocks, we can generate 2**n collisions.
        self.colliding_blocks = []
        self.current_state = self.hash_cls()._state
        self.n = 0  # Number of steps that we ran (2**n collisions).
        self.num_calls = 0  # Total calls made to the hash function.

    def next(self):
        """Finds the next colliding block, from the current state.

        This doubles our total collision count.
        """
        state_to_block = {}
        while True:
            block = random_helper.random_bytes(self.hash_cls.BLOCK_SIZE)
            state = tuple(self.current_state)
            state = self.hash_cls.process_chunk(block, state)
            self.num_calls += 1
            if state in state_to_block and block != state_to_block[state]:
                # New collision!
                self.colliding_blocks.append((block, state_to_block[state]))
                break
            state_to_block[state] = block
        self.current_state = state
        self.n += 1

    def num_collisions(self):
        return 2**self.n

    def all_collisions(self):
        return (b"".join(blocks)
                for blocks in itertools.product(*self.colliding_blocks))
