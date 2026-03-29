#!/usr/bin/env python3
"""HOTP/TOTP one-time password generator."""
import hashlib, hmac, struct, time

def hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    h = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = h[-1] & 0x0f
    code = struct.unpack(">I", h[offset:offset+4])[0] & 0x7fffffff
    return str(code % (10 ** digits)).zfill(digits)

def totp(secret: bytes, period: int = 30, digits: int = 6, t: float = None) -> str:
    if t is None:
        t = time.time()
    counter = int(t) // period
    return hotp(secret, counter, digits)

if __name__ == "__main__":
    import sys, base64
    if len(sys.argv) < 2:
        print("Usage: otp_gen.py <base32_secret> [--hotp <counter>]")
        sys.exit(1)
    secret = base64.b32decode(sys.argv[1].upper())
    if len(sys.argv) > 2 and sys.argv[2] == "--hotp":
        print(hotp(secret, int(sys.argv[3])))
    else:
        print(totp(secret))

def test():
    # RFC 4226 test vector
    secret = b"12345678901234567890"
    expected = ["755224","287082","359152","969429","338314","254676","287922","162583","399871","520489"]
    for i, exp in enumerate(expected):
        assert hotp(secret, i) == exp, f"HOTP counter={i}: {hotp(secret, i)} != {exp}"
    # TOTP at known time
    code = totp(secret, t=59)
    assert len(code) == 6
    assert code.isdigit()
    # Same time = same code
    assert totp(secret, t=100) == totp(secret, t=100)
    # Different period = different code (usually)
    print("  otp_gen: ALL TESTS PASSED")
