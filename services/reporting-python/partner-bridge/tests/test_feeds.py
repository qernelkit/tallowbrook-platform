import os
import struct

from partner_bridge import digests, feeds


def _header(version=3, partner_id=7, message_no=1):
    return feeds.HEADER.pack(feeds.FEED_MAGIC, version, partner_id, os.urandom(16), message_no)


def test_header_round_trip():
    header = feeds.parse_header(_header() + b"rest")
    assert header["version"] == 3
    assert header["partner_id"] == 7


def test_bad_magic_is_rejected():
    blob = struct.pack(">4sBH16sQ", b"XXXX", 3, 1, os.urandom(16), 0)
    try:
        feeds.parse_header(blob)
    except feeds.FeedError:
        return
    raise AssertionError("bad magic accepted")


def test_records_are_checked():
    segment = "SEG01"
    trailer = "%08x" % digests.segment_checksum(segment.encode("ascii"))
    text = "# partner 7\n%s|4000123412341234|12.50|USD|%s\n" % (segment, trailer)
    records = feeds.parse_records(text)
    assert records == [
        {"segment": "SEG01", "account": "4000123412341234", "amount": "12.50", "currency": "USD"}
    ]


def test_luhn_digit():
    assert digests.account_digest("7992739871") == "79927398713"
