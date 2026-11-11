#!/usr/bin/env python3
"""Qt-free bus operations for the VBFlasher GUI.

Everything here reuses the proven CLI building blocks (vbf.Ecu, vbflasher's
session/unlock preamble, ecu_db secrets). Long, risky operations (flash,
memread, memwrite, silence, routine) are NOT done here: the GUI runs the CLI
itself as a subprocess for those, so the proven code path is exactly the one
the command line uses.

Functions print progress the same way the CLI does; the GUI captures stdout
of its worker thread into the log pane.
"""
import os
import time
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Optional

import ecu_db
import vbflasher as vf
from vbf import Ecu, Keepalive, fmt, dtc_code, dtc_status_str, dtc_is_actual  # noqa: F401

HERE = os.path.dirname(os.path.realpath(__file__))
CLI = os.path.join(HERE, "vbflasher.py")
LOG_DIR = os.path.join(HERE, "logs")
BACKUP_DIR = os.path.join(LOG_DIR, "backups")

IDENT_DIDS = ("F110", "F111", "F113", "F188", "F124", "F190", "F18C")


class OpError(Exception):
    pass


def can_ifaces():
    """SocketCAN interfaces present on this host (ARPHRD_CAN = 280)."""
    out = []
    try:
        for n in sorted(os.listdir("/sys/class/net")):
            try:
                with open(f"/sys/class/net/{n}/type") as f:
                    if f.read().strip() == "280":
                        out.append(n)
            except OSError:
                pass
    except OSError:
        pass
    return out


def iface_state(iface):
    up = vf.iface_is_up(iface)
    return "up" if up else ("DOWN" if up is False else "?")


@dataclass
class Target:
    """What the user selected: a registered profile (or a raw CAN id) + iface."""
    txid: int
    iface: str
    profile: Optional[ecu_db.EcuProfile] = None
    rxid: Optional[int] = None

    @property
    def rx(self):
        if self.rxid is not None:
            return self.rxid
        return self.profile.resp_id() if self.profile else self.txid + 8

    @property
    def name(self):
        return self.profile.name if self.profile else f"0x{self.txid:03X}"

    @property
    def short(self):
        """Token the CLI accepts as an ECU selector."""
        if self.profile and self.profile.aliases:
            return self.profile.aliases[0]
        return f"0x{self.txid:03X}"


class Link:
    """An open ISO-TP connection to one module; use as a context manager."""

    def __init__(self, target: Target, log_name="gui"):
        self.t = target
        if not os.path.exists(f"/sys/class/net/{target.iface}"):
            raise OpError(f"interface {target.iface} does not exist")
        if vf.iface_is_up(target.iface) is False:
            raise OpError(f"interface {target.iface} is DOWN")
        os.makedirs(LOG_DIR, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        tag = (target.short or "ecu").replace("/", "_")
        self.logf = open(os.path.join(LOG_DIR, f"{stamp}_{tag}_{log_name}.log"), "w")
        self.ecu = Ecu(target.iface, target.txid, target.rx, execute=True, logfile=self.logf)
        self.ka = None
        self.hw = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        self.stop_keepalive()
        try:
            if self.ecu.s:
                self.ecu.s.close()
        except OSError:
            pass
        try:
            self.logf.close()
        except OSError:
            pass

    # -- basic services -------------------------------------------------
    def wake(self, tries=3, timeout=0.4):
        return self.ecu.wake(tries=tries, timeout=timeout)

    def read(self, did: int, timeout=3.0):
        """(payload, None) or (None, error text)."""
        r = self.ecu.req(f"22{did:04X}", timeout=timeout, what=f"22 {did:04X}")
        if r is None:
            return None, "no response"
        if r[0] == 0x7F:
            return None, fmt(r)
        if r[0] != 0x62 or len(r) < 3 or (r[1] << 8 | r[2]) != did:
            return None, f"unexpected {r.hex().upper()}"
        return bytes(r[3:]), None

    def write(self, did: int, data: bytes, timeout=5.0):
        r = self.ecu.req(f"2E{did:04X}{data.hex()}", timeout=timeout,
                         what=f"2E {did:04X} writeDataByIdentifier")
        if r is not None and r and r[0] == 0x6E:
            return True, "6E"
        return False, fmt(r)

    def ident(self, dids=IDENT_DIDS, timeout=1.5):
        out = {}
        for d in dids:
            p, err = self.read(int(d, 16), timeout=timeout)
            out[d] = p
        f111 = out.get("F111")
        if f111:
            self.hw = text(f111)
        return out

    def session(self, sess: Optional[int]):
        if sess is None or sess == 0x01:
            return
        r = self.ecu.req(f"10{sess:02X}", timeout=5.0, what=f"10 {sess:02X} session")
        if not (r and r[0] == 0x50):
            raise OpError(f"10 {sess:02X} diagnosticSession: {fmt(r)}")
        print(f"   OK   10 {sess:02X} session")
        time.sleep(0.1)

    def unlock(self, level: int, secret: Optional[bytes] = None, settle=True):
        """27 level/level+1 with the ecu_db secret for the live F111 (or the
        explicit `secret`). Re-uses the CLI preamble so behaviour is identical."""
        prof = self.t.profile
        algo = None             # explicit secret: _session_and_unlock resolves it
        if secret is None:
            if prof is None:
                raise OpError("custom CAN id: give the 5-byte secret explicitly")
            hw = self.hw
            if hw is None:
                p, _ = self.read(0xF111)
                hw = self.hw = text(p) if p else ""
            secret = prof.pick_secret(hw or "", level)
            if secret is None:
                raise OpError(f"no secret in ecu_db for {prof.name} F111 {hw!r} level {level}")
            # keygen follows the same rule (CGEA IPMA: 16-byte HMAC seeds)
            algo = prof.pick_algo(hw or "", level)
        args = SimpleNamespace(session=None, unlock=True, sec_level=level, secret=secret,
                               hw=None, timeout=5.0, seed_delay=vf.SEED_DELAY, algo=algo)
        if settle:
            vf.settle_before_seed(vf.SEED_DELAY)
        try:
            vf._session_and_unlock(args, prof or _Anon(), self.ecu)
        except SystemExit as e:
            raise OpError(str(e))

    def start_keepalive(self, period=1.5):
        if self.ka is None:
            self.ka = Keepalive(self.ecu, period=period).start()

    def stop_keepalive(self):
        if self.ka is not None:
            try:
                self.ka.stop()
            finally:
                self.ka = None

    def reset(self, mode=0x01):
        return self.ecu.reset(mode=mode)

    def read_dtcs(self, mask=0xFF):
        return self.ecu.read_dtcs(status_mask=mask)

    def clear_dtcs(self, group=0xFFFFFF):
        return self.ecu.clear_dtcs(group=group)


class _Anon:
    name = "custom"

    def pick_secret(self, *a, **k):
        return None


def text(b):
    if not b:
        return ""
    return b.decode("latin-1", "replace").rstrip("\x00 ").strip()


def first_session(s: str) -> Optional[int]:
    """'01 03 60' -> None (default session OK); '03 60' -> 0x03."""
    toks = (s or "").split()
    if not toks or "01" in toks:
        return None
    try:
        return int(toks[0], 16)
    except ValueError:
        return None


def ford_level_to_seed(level: Optional[str]) -> Optional[int]:
    """Ford 'security_level_N' -> requestSeed subfunction 2N-1 (L1=27 01, L2=27 03)."""
    if not level:
        return None
    try:
        n = int(level)
    except ValueError:
        return None
    return 2 * n - 1


def ccc_erase_len(profile, hw: str) -> int:
    """Sector erase length for the CCC write (FoCCCus writeCccToEcu)."""
    hw = (hw or "").upper()
    if profile is not None and profile.txid == 0x720:
        return 0x1000
    if hw.startswith(("DV6T", "F1FT", "F1DT")):
        return 0x4000
    return 0x400


def cli_cmd(*args):
    """argv for running the CLI with the same interpreter, unbuffered."""
    import sys
    return [sys.executable, "-u", CLI, *[str(a) for a in args]]
