#!/usr/bin/env python3
"""SecurityAccess keygens for the CGEA IPMA (Delphi/Aptiv RH850 + EyeQ3, 0x706).

The CGEA camera generation (core hardware JX7T-14F403-*, apps N1BT/JX7T/L1TT/
LB5T/LM2T-14F397) does NOT use the universal 3-byte Ford LFSR (ford_seckey).
It uses 16-byte seeds and HMAC-SHA1 with two 12-byte ASCII secrets that sit
back to back ("DELPHIIPMA0130AMPIIHPLED") in every app and in the PBL:

  application, level 3 (extended session 10 03, 27 03/04):
      key16 = HMAC-SHA1(b"30AMPIIHPLED", b"zaCK" + seed16)[4:20]
      VERIFIED: 3/3 UCDS captured pairs (IPMA/EyeQ3/hs2_ipma_ucds.log)

  primary bootloader, level 1 (programming session 10 02, 27 01/02):
      key18 = HMAC-SHA1(b"DELPHIIPMA01", seed16 + b"JaKe")[0:18]
      VERIFIED live 2026-11-08 (67 02, then SBL load + start).
      The PBL compares all 18 bytes: FUN_00001168 runs a 9-byte body twice
      via the RH850 LOOP instruction, which Ghidra mis-decodes as mulhi.

Level 1 is offered only by the PBL (27 01 in session 03 -> NRC 7E), level 3
only by the application (27 03 in session 02 -> NRC 12), so the level fully
selects the algorithm. Provenance: IPMA/EyeQ3/README.md section 7.

ALGOS maps the ecu_db SecretRule.algo name to (seed length, keygen).
"""
import hashlib
import hmac

APP_PREFIX = b"zaCK"
PBL_SUFFIX = b"JaKe"


def key_app(seed16: bytes, secret: bytes) -> bytes:
    seed16 = bytes(seed16)
    if len(seed16) != 16:
        raise ValueError(f"CGEA seed must be 16 bytes, got {len(seed16)}")
    return hmac.new(bytes(secret), APP_PREFIX + seed16, hashlib.sha1).digest()[4:20]


def key_pbl(seed16: bytes, secret: bytes) -> bytes:
    seed16 = bytes(seed16)
    if len(seed16) != 16:
        raise ValueError(f"CGEA seed must be 16 bytes, got {len(seed16)}")
    return hmac.new(bytes(secret), seed16 + PBL_SUFFIX, hashlib.sha1).digest()[0:18]


ALGOS = {
    "cgea_app": (16, key_app),
    "cgea_pbl": (16, key_pbl),
}

SECRET_L1 = b"DELPHIIPMA01"
SECRET_L3 = b"30AMPIIHPLED"

# (algo, secret, seed hex, key hex) -- every pair was accepted by a real module
VECTORS = [
    ("cgea_app", SECRET_L3, "cc9463e0311da02a8e56e929a7a851d5",
     "959f5af1047a68f00d17b8c45145af80"),
    ("cgea_app", SECRET_L3, "58d213a50dc22ea83a0a1013e3822cb5",
     "41e1ebbc50642b8eee73bfa50d5a0a7e"),
    ("cgea_app", SECRET_L3, "a404bdf0a9e0270aa6b44e70df0c539b",
     "aaf7772d6ba1ab5ee345711d523c5598"),
    ("cgea_pbl", SECRET_L1, "10524001e531f401321d4f667bfae457",
     "7325a3e9ca302318920e25ed70680f93808f"),
]


def selftest() -> bool:
    ok = True
    for algo, sec, seed, key in VECTORS:
        got = ALGOS[algo][1](bytes.fromhex(seed), sec).hex()
        good = got == key
        ok = ok and good
        print(f"  {'PASS' if good else 'FAIL'}  {algo} seed {seed[:8]}.. -> {got}")
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if selftest() else 1)
