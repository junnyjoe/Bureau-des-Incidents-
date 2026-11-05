import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote


def generate_totp_secret(length=32):
    """Generate a cryptographically secure random base32 secret string (RFC 4648)."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def get_totp_code(secret, for_time=None, time_step=30, digits=6):
    """
    Compute the standard 6-digit TOTP token (RFC 6238 / RFC 4226) for the given secret.
    Pure Python standard library implementation with zero external dependencies.
    """
    if for_time is None:
        for_time = time.time()
    counter = int(for_time // time_step)

    # Pad secret if length is not a multiple of 8
    pad = (8 - (len(secret) % 8)) % 8
    key = base64.b32decode(secret.upper() + ("=" * pad))

    # Pack counter as an 8-byte big-endian unsigned integer
    msg = struct.pack(">Q", counter)

    # HMAC-SHA1
    h = hmac.new(key, msg, hashlib.sha1).digest()

    # Dynamic truncation (RFC 4226 section 5.4)
    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
    token = code_int % (10**digits)
    return f"{token:0{digits}d}"


def verify_totp_code(secret, code, window=1, time_step=30, digits=6):
    """
    Verify a TOTP code against a secret with time drift allowance (+/- 1 time step).
    """
    if not secret or not code:
        return False
    clean_code = str(code).strip()
    current_time = time.time()
    for drift in range(-window, window + 1):
        expected = get_totp_code(
            secret,
            for_time=current_time + (drift * time_step),
            time_step=time_step,
            digits=digits,
        )
        if hmac.compare_digest(expected, clean_code):
            return True
    return False


def get_totp_uri(secret, username, issuer="IncidentDesk"):
    """
    Generate an otpauth:// URI compatible with Google Authenticator, Aegis, Bitwarden, etc.
    """
    encoded_issuer = quote(issuer)
    encoded_user = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{encoded_user}?secret={secret}&issuer={encoded_issuer}&digits=6&period=30"
