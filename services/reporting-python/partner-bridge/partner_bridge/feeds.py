import logging
import os
import struct

from partner_bridge import digests, envelopes, integrity, passphrases
from partner_bridge.account_tokens import tokenize_account
from partner_bridge.block_seal import BlockSealer

log = logging.getLogger(__name__)

FEED_MAGIC = b"TBPF"
HEADER = struct.Struct(">4sBH16sQ")  # magic, version, partner id, salt, message number
TAG_LEN = 64


class FeedError(ValueError):
    pass


def parse_header(blob):
    if len(blob) < HEADER.size:
        raise FeedError("feed shorter than header")
    magic, version, partner_id, salt, message_no = HEADER.unpack_from(blob)
    if magic != FEED_MAGIC:
        raise FeedError("not a partner feed")
    if version not in (2, 3):
        raise FeedError("unsupported feed version %d" % version)
    return {
        "version": version,
        "partner_id": partner_id,
        "salt": salt,
        "message_no": message_no,
    }


def parse_records(text):
    records = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        fields = line.split("|")
        if len(fields) != 5:
            raise FeedError("line %d: expected 5 fields, got %d" % (lineno, len(fields)))
        segment, account, amount, currency, trailer = fields
        if int(trailer, 16) != digests.segment_checksum(segment.encode("ascii")):
            raise FeedError("line %d: segment checksum mismatch" % lineno)
        records.append(
            {"segment": segment, "account": account, "amount": amount, "currency": currency}
        )
    return records


def read_feed(blob, phrase):
    header = parse_header(blob)
    body, tag = blob[HEADER.size : -TAG_LEN], blob[-TAG_LEN:]
    feed_key = passphrases.feed_key_from_passphrase(phrase, header["salt"])
    if not integrity.check_feed_tag(feed_key, blob[:-TAG_LEN], tag):
        raise FeedError("feed tag does not match")
    if header["version"] == 3:
        plain = envelopes.open_feed(feed_key, body)
    else:
        plain = BlockSealer(feed_key).apply(header["message_no"], body)
    return header, parse_records(plain.decode("ascii"))


def outbound_records(records, token_key_hex):
    out = []
    for r in records:
        account = digests.account_digest(r["account"])
        out.append(dict(r, account=tokenize_account(token_key_hex, account)))
    return out


def token_key_from_env():
    value = os.environ.get("PARTNER_BRIDGE_TOKEN_KEY", "")
    if len(value) != 64:
        raise RuntimeError("PARTNER_BRIDGE_TOKEN_KEY must be 64 hex characters")
    return value


def dispatch(blob, phrase, handlers):
    header, records = read_feed(blob, phrase)
    handler = handlers.get(header["partner_id"])
    if handler is None:
        log.warning(
            "no handler for partner %d, %d records parked", header["partner_id"], len(records)
        )
        return 0
    handler(outbound_records(records, token_key_from_env()))
    return len(records)
