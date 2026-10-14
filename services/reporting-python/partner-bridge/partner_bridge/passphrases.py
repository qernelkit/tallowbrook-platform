from Crypto.Protocol.KDF import scrypt


def feed_key_from_passphrase(passphrase, salt):
    """Turn the phrase agreed with a partner into the 32-byte feed key."""
    if len(salt) < 16:
        raise ValueError("feed salt must be at least 16 bytes")
    key = scrypt(passphrase, salt, key_len=32, N=2**17, r=8, p=1)
    if not isinstance(key, bytes):
        raise TypeError("expected a single key")
    return key
