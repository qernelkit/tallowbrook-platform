from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# Agreed with the rail carrier in 2019; rotation needs a change request on their side.
RAIL_SETTLEMENT_KEY = bytes.fromhex("57e5b6ce080e4f80dff8fd689db9c4467a1cf18301fd7345")

RECORD_FIELDS = ("waybill", "car_number", "origin", "destination", "tonnes", "amount_cents")


def settlement_record(row):
    missing = [f for f in RECORD_FIELDS if f not in row]
    if missing:
        raise ValueError("settlement row is missing %s" % ", ".join(missing))
    return "|".join(str(row[f]) for f in RECORD_FIELDS).encode("ascii")


def encrypt_settlement(record):
    iv = get_random_bytes(8)
    cipher = DES3.new(RAIL_SETTLEMENT_KEY, DES3.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(record, 8))


def settlement_file(rows):
    lines = [encrypt_settlement(settlement_record(r)).hex() for r in rows]
    return ("\n".join(lines) + "\n").encode("ascii")
