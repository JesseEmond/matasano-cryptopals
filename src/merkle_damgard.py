class Hash():
    # The following parameters can be overloaded by children classes
    # if needed.
    BLOCK_SIZE = 64
    ENCODED_LEN_SIZE = 8  # Store length as 64-bits
    ENDIANNESS = "big"

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
        msg_len_bits = msg_len * 8
        padding.extend(msg_len_bits.to_bytes(cls.ENCODED_LEN_SIZE, cls.ENDIANNESS))
        return bytes(padding)

    def __init__(self, iv, msg_len=0):
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
        assert len(self._unprocessed) % 64 == 0
        self._process_unprocessed()
        assert len(self._unprocessed) == 0
        return b"".join(h.to_bytes(4, self.ENDIANNESS) for h in self._state)

    def process_chunk(self, chunk, state):
        raise NotImplementedError("process_chunk")

    def _process_unprocessed(self):
        while len(self._unprocessed) >= self.BLOCK_SIZE:
            self._state = self.process_chunk(self._unprocessed[:self.BLOCK_SIZE], self._state)
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