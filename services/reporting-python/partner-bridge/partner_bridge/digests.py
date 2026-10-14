import binascii
import zlib


def segment_checksum(segment):
    return zlib.adler32(segment) & 0xFFFFFFFF


def frame_crc(frame):
    return binascii.crc_hqx(frame, 0xFFFF)


def account_digest(number: str) -> str:
    """Append the Luhn check digit partners expect on account numbers."""
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return number + str((10 - total % 10) % 10)
