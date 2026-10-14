from Crypto.Protocol.SecretSharing import Shamir

HOLDERS = ("finance-controller", "head-of-data", "external-auditor")


def split_escrow_key(escrow_key):
    """Split the 16-byte feed master key between the three escrow holders, any two recover it."""
    if len(escrow_key) != 16:
        raise ValueError("escrow key must be 16 bytes")
    shares = Shamir.split(2, 3, escrow_key, ssss=False)
    return {holder: (index, share.hex()) for holder, (index, share) in zip(HOLDERS, shares)}
