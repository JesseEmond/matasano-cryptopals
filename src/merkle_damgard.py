import itertools
import math

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

    def state(self):
        """Useful for collision methods."""
        return self._state

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
        return self.state_to_digest(self._state)

    @classmethod
    def state_to_digest(cls, state):
        return b"".join(h.to_bytes(cls.STATE_ENTRY_SIZE, cls.ENDIANNESS)
                        for h in state)

    @classmethod
    def process_chunk(cls, chunk, state):
        raise NotImplementedError("process_chunk")

    @classmethod
    def process_blocks(cls, msg, state):
        """Returns (msg_unprocessed, state)."""
        while len(msg) >= cls.BLOCK_SIZE:
            chunk = msg[:cls.BLOCK_SIZE]
            state = cls.process_chunk(chunk, state)
            assert len(state) == cls.STATE_ENTRIES
            msg = msg[cls.BLOCK_SIZE:]
        return msg, state

    def _process_unprocessed(self):
        self._unprocessed, self._state = self.process_blocks(
                self._unprocessed, self._state)

    @classmethod
    def random_block(cls):
        return random_helper.random_bytes(cls.BLOCK_SIZE)

    @classmethod
    def init_state(cls):
        return cls().state()

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
    def generate_multicollisions(cls, n, verbose=False):
        """Yields 2**n collisions."""
        generator = MulticollisionGenerator(cls)
        for i in range(n):
            generator.next()
            if verbose:
                print(f"  ... found {i+1}/{n} colliding blocks...")
        if verbose:
            print(f"Made {generator.num_calls} hash calls in total.")
        return generator.all_collisions()

    @classmethod
    def second_preimage_collision(cls, msg, verbose=False):
        """Find m s.t. H(m) = H(msg). |msg| must have 2**k blocks, int k."""
        k = round(math.log2(len(msg) / cls.BLOCK_SIZE))
        assert 2**k * cls.BLOCK_SIZE == len(msg), "Length not supported."
        if verbose:
            print(f"2nd preimage collision, using k={k}")
        expandable = ExpandableMessages(cls, k)
        intermediate = {}
        state = cls.init_state()
        for i in range(len(msg) // cls.BLOCK_SIZE):
            block = msg[i * cls.BLOCK_SIZE:(i+1) * cls.BLOCK_SIZE]
            if i > k:  # Need at least k+1 of prefix+bridge.
                intermediate[state] = i
            state = cls.process_chunk(block, state)
        bridge_state, bridge = _block_collision_into(
                cls, expandable.final_state, intermediate)
        suffix_idx = intermediate[bridge_state]
        suffix = msg[suffix_idx * cls.BLOCK_SIZE:]
        prefix_len = len(msg) - len(bridge) - len(suffix)
        assert prefix_len % cls.BLOCK_SIZE == 0
        prefix = expandable.expand_to(prefix_len // cls.BLOCK_SIZE)
        collision = prefix + bridge + suffix
        assert len(collision) == len(msg)
        return collision

    @classmethod
    def nostradamus(cls, k, msg_len, verbose=False):
        """Precompute 2**k glue hashes for given |msg|, creates a hash funnel.

        Later use the given 'generator' to produce glue to get the given hash
        using our pre-computed funnel. Increase k to move processing to
        pre-computation.

        Returns:
            (digest, generator)
        """
        generator = NostradamusGenerator(cls, k, msg_len, verbose=verbose)
        return generator.digest, generator


class MulticollisionGenerator:
    """Helper class to iteratively generate more collisions of a MD hash."""
    def __init__(self, hash_cls):
        self.hash_cls = hash_cls
        # Sequential pairs of blocks that give a collision under hash_cls.
        # With n pairs of colliding blocks, we can generate 2**n collisions.
        self.colliding_blocks = []
        self.current_state = self.hash_cls.init_state()
        self.n = 0  # Number of steps that we ran (2**n collisions).
        self.num_calls = 0  # Total calls made to the hash function.

    def next(self):
        """Finds the next colliding block, from the current state.

        This doubles our total collision count.
        """
        def on_hash():
            self.num_calls += 1
        state = tuple(self.current_state)
        state, block1, block2 = _block_collision_single(
                self.hash_cls, state, on_hash_call=on_hash)
        self.colliding_blocks.append((block1, block2))
        self.current_state = state
        self.n += 1

    def num_collisions(self):
        return 2**self.n

    def all_collisions(self):
        return (b"".join(blocks)
                for blocks in itertools.product(*self.colliding_blocks))


class ExpandableMessages:
    """Helper to find a second preimage collision."""

    def __init__(self, hash_cls, k, verbose=False):
        """Generate expandable messages to collide lengths [k, k+2**k-1]."""
        self.k = k
        self.hash_cls = hash_cls
        self.short_blocks = []  # For single-block decisions.
        self.long_blocks = []  # For 2**i block decisions.

        state = hash_cls().state()
        for i in reversed(range(k)):
            long = bytearray()
            long_state = state
            for _ in range(2**i):  # Generate 2**i blocks before our 2**i+1th.
                block = self.hash_cls.random_block()
                long_state = self.hash_cls.process_chunk(block, long_state)
                long.extend(block)
            state, short_block, long_block = _block_collision_parallel(
                    self.hash_cls, state, long_state)
            long.extend(long_block)
            self.short_blocks.append(short_block)
            self.long_blocks.append(bytes(long))

        self.final_state = state

    def expand_to(self, n):
        """Generate n blocks (in [k, k+2**k-1]) that produce 'final_state'."""
        assert self.k <= n <= self.k + 2**self.k - 1, n
        message = bytearray()
        binary = bin(n - self.k)[2:].zfill(self.k)
        for i, bit in enumerate(binary):
            if bit == "0":
                message.extend(self.short_blocks[i])
            else:
                message.extend(self.long_blocks[i])
        return bytes(message)


class NostradamusGenerator:
    """Helper class to generate a hash that we later find the message for."""

    def __init__(self, hash_cls, k, msg_len, verbose=False):
        """Precomputes 2**k states to collide into for a msg with |msg|=msg_len.

        Tune as needed; k > state_bits/2 will speed up the collision but take
        more preprocessing, and vice-versa.
        """
        assert msg_len % hash_cls.BLOCK_SIZE == 0, (
            "|msg_len| must be a multiple of block size.")
        assert k > 0
        self.k = k
        self.msg_len = msg_len
        self.funnel = []  # k elements, each a map from state to block.
        self.hash_cls = hash_cls
        states = set()
        while len(states) < 2**k:
            block = hash_cls.random_block()
            states.add(hash_cls.process_chunk(block, hash_cls.init_state()))
        states = list(states)
        for i in reversed(range(k)):
            if verbose:
                print(f"  .. creating funnel for 2**{i+1} states..")
            new_states = []
            state_to_block = {}
            for i in range(0, len(states), 2):
                left, right = states[i:i+2]
                new_state, left_block, right_block = _block_collision_parallel(
                        hash_cls, left, right)
                new_states.append(new_state)
                state_to_block[left] = left_block
                state_to_block[right] = right_block
            self.funnel.append(state_to_block)
            states = new_states
        assert len(states) == 1
        final_state = next(iter(states))
        if verbose:
            print("  funnel created")
        padding = hash_cls.length_padding(msg_len)
        _, digest_state = hash_cls.process_blocks(padding, final_state)
        self.digest = hash_cls.state_to_digest(digest_state)

    def get_message(self, prefix, pad_char=None):
        """Produces message m with the given prefix with H(m) = self.digest.

        If the prefix length is too short for the pre-computed msg_len, pad
        using pad_char. If none is given or if the prefix is too long, raise
        ValueError.
        """
        glue_len = (self.k + 1) * self.hash_cls.BLOCK_SIZE
        if len(prefix) + glue_len > self.msg_len:
            raise ValueError(
                    f"Prefix len ({len(prefix)}) with glue ({glue_len}) too "
                    f"long for pre-computed length ({self.msg_len})")
        elif len(prefix) + glue_len < self.msg_len:
            if pad_char is None:
                raise ValueError(
                        f"Prefix len ({len(prefix)}) with glue ({glue_len}) "
                        f"too short for pre-computed length ({self.msg_len}), "
                        f"and no pad_char was given.")
            pad = pad_char * (self.msg_len - glue_len - len(prefix))
            prefix += pad.encode("ascii")
        assert len(prefix) + glue_len == self.msg_len
        return prefix + self._get_glue(prefix)

    def _get_glue(self, prefix):
        assert len(prefix) % self.hash_cls.BLOCK_SIZE == 0
        _, state = self.hash_cls.process_blocks(
                prefix, self.hash_cls.init_state())
        leaves = self.funnel[0]
        state, bridge = _block_collision_into(self.hash_cls, state, leaves)
        glue = bytearray()
        glue.extend(bridge)
        for state_to_block in self.funnel:
            assert state in state_to_block
            block = state_to_block[state]
            glue.extend(block)
            state = self.hash_cls.process_chunk(block, state)
        assert len(glue) == (self.k + 1) * self.hash_cls.BLOCK_SIZE
        return glue


def _block_collision_single(hash_cls, state, on_hash_call=None):
    """Find 2 blocks where H(block1, state) = H(block2, state).

    on_hash_call is called (without args) on every hashing call.

    Returns:
        (colliding_state, block1, block2)
    """
    seen = {}
    while True:
        block = hash_cls.random_block()
        h = hash_cls.process_chunk(block, state)
        if on_hash_call:
            on_hash_call()
        if h in seen and seen[h] != block:
            return h, block, seen[h]
        seen[h] = block


def _block_collision_parallel(hash_cls, left_state, right_state):
    """Find 2 blocks that collide starting from distinct states.

    Returns:
        (colliding_state, left_block, right_block)
    """
    left_seen = {}
    right_seen = {}
    while True:
        block = hash_cls.random_block()
        left_hash = hash_cls.process_chunk(block, left_state)
        if left_hash in right_seen:
            return left_hash, block, right_seen[left_hash]
        left_seen[left_hash] = block
        right_hash = hash_cls.process_chunk(block, right_state)
        if right_hash in left_seen:
            return right_hash, left_seen[right_hash], block
        right_seen[right_hash] = block


def _block_collision_into(hash_cls, state, collision_states):
    """Find 'block' where H(block, state) is in collision_states.

    Returns:
        (colliding_state, block)
    """
    while True:
        block = hash_cls.random_block()
        h = hash_cls.process_chunk(block, state)
        if h in collision_states:
            return h, block
