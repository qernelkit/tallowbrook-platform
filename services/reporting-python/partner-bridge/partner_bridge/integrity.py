import hmac

from Crypto.Hash import KMAC256


def feed_tag(feed_key, body):
    mac = KMAC256.new(key=feed_key, mac_len=64, custom=b"tb-partner-feed")
    mac.update(body)
    return mac.digest()


def check_feed_tag(feed_key, body, tag):
    return hmac.compare_digest(feed_tag(feed_key, body), tag)
