#!/usr/bin/env python3
"""Universal Ford SecurityAccess keygen.

ONE algorithm serves every Ford ECU in this project. It is a 64-round LFSR over
an 8-byte state parameterised by a 5-byte secret. keygen_equivalence in the PSCM
project proved that the BCM's key_from_seed (secret 64000B0C59), the PSCM form
(MAGIC 0x9B2533) and the IPMA generalised form all produce BYTE-IDENTICAL keys
under the mapping "5-byte secret, most-significant byte first == big-endian".

This module is the single source of truth. selftest() cross-checks it against
the hardware-proven BCM implementation so a divergent copy can never ship.

    key = key_from_seed(seed3, secret5)
      seed3   : 3 bytes from the 0x27 0x01 positive response (bytes/list)
      secret5 : 5-byte secret, MSB first (bytes) OR a 40-bit int
      returns : 3-byte key for 0x27 0x02
"""


def _as_secret_bytes(secret) -> bytes:
    if isinstance(secret, int):
        return secret.to_bytes(5, "big")
    b = bytes(secret)
    if len(b) != 5:
        raise ValueError(f"secret must be 5 bytes, got {len(b)}")
    return b


def key_from_seed(seed3, secret) -> bytes:
    s = _as_secret_bytes(secret)
    s0, s1, s2, s3, s4 = s[0], s[1], s[2], s[3], s[4]
    seed = list(seed3)
    seed_int = (seed[0] << 16) + (seed[1] << 8) + seed[2]
    or_ed = (((seed_int & 0xFF0000) >> 16) | (seed_int & 0xFF00)
             | (s0 << 24) | ((seed_int & 0xFF) << 16))
    m = 0xC541A9

    def rnd(inbit, m):
        a = (inbit ^ (m & 1)) << 23
        v = a | (m >> 1)
        t = (v & 0x800000) >> 23
        return (v & 0xEF6FD7
                | ((((v & 0x100000) >> 20) ^ t) << 20)
                | (((((m >> 1) & 0x8000) >> 15) ^ t) << 15)
                | (((((m >> 1) & 0x1000) >> 12) ^ t) << 12)
                | (32 * ((((m >> 1) & 0x20) >> 5) ^ t))
                | (8 * ((((m >> 1) & 8) >> 3) ^ t)))

    for i in range(32):
        m = rnd((or_ed >> i) & 1, m)
    w = (s4 << 24) | (s3 << 16) | s1 | (s2 << 8)
    for j in range(32):
        m = rnd((w >> j) & 1, m)

    key = (((m & 0xF0000) >> 16) | (16 * (m & 0xF))
           | ((((m & 0xF00000) >> 20) | ((m & 0xF000) >> 8)) << 8)
           | ((m & 0xFF0) >> 4 << 16))
    return bytes([(key & 0xFF0000) >> 16, (key & 0xFF00) >> 8, key & 0xFF])


def selftest(verbose=True):
    ok = True

    def chk(name, cond, detail=""):
        nonlocal ok
        ok = ok and bool(cond)
        if verbose:
            print(f"  {'PASS' if cond else 'FAIL'}  {name}"
                  + (f"  {detail}" if detail else ""))

    # published vector (secret 0xFA5FC0 -> 00 FA 5F C0 as low bytes; MSB form
    # 0x0000FA5FC0). This is the vector both BCM and PSCM tools assert.
    chk("published vector seed 1F7C69 secret 0xFA5FC0 -> 9a64ce",
        key_from_seed([0x1F, 0x7C, 0x69], 0x0000FA5FC0).hex() == "9a64ce",
        key_from_seed([0x1F, 0x7C, 0x69], 0x0000FA5FC0).hex())

    # int secret and byte secret must agree
    chk("int-secret == bytes-secret",
        key_from_seed([0x11, 0x22, 0x33], 0x64000B0C59)
        == key_from_seed([0x11, 0x22, 0x33], bytes.fromhex("64000B0C59")))

    # cross-check against the HARDWARE-PROVEN BCM implementation if present
    import importlib.util
    import os
    bp = "/home/gl/Projects/ford/BCM/Research/work/flash/bcmflash.py"
    if os.path.exists(bp):
        spec = importlib.util.spec_from_file_location("bcmflash", bp)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        seeds = [(0, 0, 8), (0x1F, 0x7C, 0x69), (0xAA, 0xBB, 0xCC),
                 (0x12, 0x34, 0x56), (0xFF, 0xFF, 0xFF)]
        agree = all(key_from_seed(s, bytes.fromhex("64000B0C59"))
                    == mod.key_from_seed(list(s)) for s in seeds)
        chk("matches bcmflash.key_from_seed on 5 seeds", agree)
    else:
        chk("bcmflash present for cross-check", False, "(BCM repo not found)")
    return ok


if __name__ == "__main__":
    import sys
    sys.exit(0 if selftest() else 1)
