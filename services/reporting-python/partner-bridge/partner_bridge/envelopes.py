from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

NONCE_LEN = 16
TAG_LEN = 16


def _eax(feed_key, nonce):
    return AES.new(feed_key, AES.MODE_EAX, nonce=nonce)


def seal_feed(feed_key, payload):
    nonce = get_random_bytes(NONCE_LEN)
    body, tag = _eax(feed_key, nonce).encrypt_and_digest(payload)
    return nonce + tag + body


def open_feed(feed_key, sealed):
    if len(sealed) < NONCE_LEN + TAG_LEN:
        raise ValueError("sealed feed is truncated")
    nonce = sealed[:NONCE_LEN]
    tag = sealed[NONCE_LEN : NONCE_LEN + TAG_LEN]
    return _eax(feed_key, nonce).decrypt_and_verify(sealed[NONCE_LEN + TAG_LEN :], tag)
