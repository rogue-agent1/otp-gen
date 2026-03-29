#!/usr/bin/env python3
"""otp_gen: HOTP/TOTP one-time password generator (RFC 4226/6238)."""
import hashlib, hmac, struct, time, sys

def hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)

def totp(secret: bytes, period: int = 30, digits: int = 6, t: float = None) -> str:
    if t is None:
        t = time.time()
    counter = int(t) // period
    return hotp(secret, counter, digits)

def verify_totp(secret: bytes, code: str, period: int = 30, window: int = 1, t: float = None) -> bool:
    if t is None:
        t = time.time()
    counter = int(t) // period
    for i in range(-window, window + 1):
        if hotp(secret, counter + i, len(code)) == code:
            return True
    return False

def test():
    # RFC 4226 test vector
    secret = b"12345678901234567890"
    expected = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
    for i, exp in enumerate(expected):
        assert hotp(secret, i) == exp, f"HOTP({i}): {hotp(secret, i)} != {exp}"
    # TOTP
    t = 59.0
    code = totp(secret, t=t)
    assert len(code) == 6
    assert verify_totp(secret, code, t=t)
    assert not verify_totp(secret, "000000", t=t, window=0)
    # Window
    code_next = totp(secret, t=t + 30)
    assert verify_totp(secret, code_next, t=t, window=1)
    # 8 digits
    code8 = hotp(secret, 0, digits=8)
    assert len(code8) == 8
    print("All tests passed!")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test()
    else:
        print("Usage: otp_gen.py test")
