from ff3 import FF3Cipher

# Fixed so the same account number gives the same token in every feed.
ACCOUNT_TWEAK = "7337cd215d330d"


def tokenize_account(key_hex, account_number):
    if len(key_hex) != 64:
        raise ValueError("account token key must be 64 hex characters")
    if not account_number.isdigit() or not 6 <= len(account_number) <= 19:
        raise ValueError("account numbers are 6 to 19 digits")
    cipher = FF3Cipher(key_hex, ACCOUNT_TWEAK)
    return cipher.encrypt(account_number)
