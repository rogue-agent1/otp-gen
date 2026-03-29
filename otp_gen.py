#!/usr/bin/env python3
"""TOTP/HOTP one-time password generator (RFC 4226/6238)."""
import sys, hashlib, hmac, struct, time

def hotp(secret, counter, digits=6):
    key = secret.encode()
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)

def totp(secret, digits=6, period=30, t=None):
    t = t or int(time.time())
    counter = t // period
    return hotp(secret, counter, digits)

def verify_totp(secret, code, window=1, period=30, t=None):
    t = t or int(time.time())
    for offset in range(-window, window + 1):
        if totp(secret, period=period, t=t + offset * period) == code:
            return True
    return False

def generate_secret(length=20):
    import base64
    raw = bytes(range(length))  # deterministic for demo
    return base64.b32encode(raw).decode().rstrip("=")

def main():
    if len(sys.argv) < 2: print("Usage: otp_gen.py <demo|test>"); return
    if sys.argv[1] == "test":
        # HOTP - deterministic
        code1 = hotp("testsecret", 0); assert len(code1) == 6; assert code1.isdigit()
        code2 = hotp("testsecret", 1); assert code2 != code1
        code3 = hotp("testsecret", 0); assert code3 == code1  # same counter = same code
        # 8 digits
        code4 = hotp("testsecret", 0, digits=8); assert len(code4) == 8
        # TOTP - same time = same code
        t = 1000000
        t1 = totp("secret", t=t); t2 = totp("secret", t=t)
        assert t1 == t2
        # Different periods = different codes (usually)
        t3 = totp("secret", t=t); t4 = totp("secret", t=t + 30)
        # Verify with window
        code = totp("mysecret", t=t)
        assert verify_totp("mysecret", code, t=t)
        assert verify_totp("mysecret", code, t=t + 25)  # within same period
        assert not verify_totp("mysecret", "000000", t=t)  # wrong code (probably)
        # Secret gen
        s = generate_secret(); assert len(s) > 0
        print("All tests passed!")
    else:
        secret = "JBSWY3DPEHPK3PXP"
        code = totp(secret)
        print(f"TOTP: {code} (valid for {30 - int(time.time()) % 30}s)")

if __name__ == "__main__": main()
