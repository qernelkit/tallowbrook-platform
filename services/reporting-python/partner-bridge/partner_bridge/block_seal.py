from Crypto.Cipher import AES

BLOCK = 16


class BlockSealer:
    """Counter-mode sealing of feed records; the counter starts at the message number."""

    def __init__(self, block_key):
        if len(block_key) not in (16, 24, 32):
            raise ValueError("block key must be 16, 24 or 32 bytes")
        self._ecb = AES.new(block_key, AES.MODE_ECB)

    def apply(self, message_no, data):
        if not 0 <= message_no < 2**64:
            raise ValueError("message number must fit in 8 bytes")
        out = bytearray()
        for i in range(0, len(data), BLOCK):
            counter = (message_no << 64) | (i // BLOCK)
            chunk = data[i : i + BLOCK]
            out.extend(a ^ b for a, b in zip(chunk, self._ecb.encrypt(counter.to_bytes(16, "big"))))
        return bytes(out)
