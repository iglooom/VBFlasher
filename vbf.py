#!/usr/bin/env python3
"""VBF container parsing + UDS/ISO-TP transport for VBFlasher.

The VBF parser is the probe-to-EOF variant from pscm_flash.py / ipma_flash.py
(handles the Hexview 0x20 separator; refuses a walk that leaves trailing bytes).
The transport is the hardware-proven ISO-TP client: TX/RX padding to DLC=8,
0x78 responsePending as CONTINUE with a clock that restarts on every pending
frame, 0x21 busyRepeatRequest retry.
"""
import binascii
import hashlib
import os
import re
import socket
import struct
import threading
import time
import zlib

# ---- ISO-TP socket options (linux/can/isotp.h) --------------------------
CAN_ISOTP = 6
SOL_CAN_ISOTP = 106
CAN_ISOTP_OPTS = 1
CAN_ISOTP_TX_PADDING = 0x004
CAN_ISOTP_RX_PADDING = 0x008

NRC = {
    0x10: "generalReject", 0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported", 0x13: "incorrectMessageLength",
    0x21: "busyRepeatRequest", 0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError", 0x31: "requestOutOfRange",
    0x33: "securityAccessDenied", 0x35: "invalidKey",
    0x36: "exceedNumberOfAttempts", 0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted", 0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure", 0x73: "wrongBlockSequenceCounter",
    0x78: "responsePending", 0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}


def human(n):
    for u, d in (("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= d:
            return "%.1f %s" % (n / d, u)
    return "%d B" % n


def fmt(r):
    if r is None:
        return "<timeout>"
    if len(r) >= 3 and r[0] == 0x7F:
        return f"NRC {r[2]:02X} {NRC.get(r[2], '?')}"
    return r.hex().upper()


# DTC status-byte bits (ISO 14229 DTCStatusMask)
DTC_STATUS_BITS = [
    (0x01, "testFailed"),
    (0x02, "testFailedThisOpCycle"),
    (0x04, "pendingDTC"),
    (0x08, "confirmedDTC"),
    (0x10, "testNotCompletedSinceLastClear"),
    (0x20, "testFailedSinceLastClear"),
    (0x40, "testNotCompletedThisOpCycle"),
    (0x80, "warningIndicatorRequested"),
]


def dtc_code(dtc: int) -> str:
    """Format a 3-byte UDS DTC as the standard code, e.g. 0x030100 -> 'P0301-00'.

    The high TWO bytes are the ISO 15031 code (letter + 4 digits); the low byte
    is the failure-type / subtype, shown after a dash.
    """
    code16 = (dtc >> 8) & 0xFFFF
    fail = dtc & 0xFF
    letter = "PCBU"[(code16 >> 14) & 0x3]
    d1 = (code16 >> 12) & 0x3
    rest = code16 & 0x0FFF
    return f"{letter}{d1}{rest:03X}-{fail:02X}"


def dtc_status_str(status: int) -> str:
    on = [name for bit, name in DTC_STATUS_BITS if status & bit]
    return ", ".join(on) if on else "-"


# "actual" fault = any real-fault bit set, i.e. NOT just the not-completed
# housekeeping bits (testNotCompletedSinceLastClear 0x10,
# testNotCompletedThisOpCycle 0x40). A bench/offline module reports mostly
# 0x50 (both not-completed) — those are noise, not present faults.
DTC_NOTCOMPLETED_MASK = 0x10 | 0x40


def dtc_is_actual(status: int) -> bool:
    return (status & ~DTC_NOTCOMPLETED_MASK) != 0


# --------------------------------------------------------------------------
# VBF
# --------------------------------------------------------------------------
class Vbf:
    def __init__(self, path):
        self.path = path
        raw = open(path, "rb").read()
        self.raw = raw
        depth, he = 0, None
        for i, c in enumerate(raw):
            if c == 0x7B:
                depth += 1
            elif c == 0x7D:
                depth -= 1
                if depth == 0:
                    he = i + 1
                    break
        if he is None:
            raise ValueError(f"{path}: no header braces found")
        self.header_text = raw[:he].decode("latin-1")
        h = self.header_text

        def field(name):
            m = re.search(name + r"\s*=\s*([^;]+);", h)
            return m.group(1).strip().strip('"').strip() if m else None

        self.part = (field("sw_part_number") or "").strip('"').strip()
        self.ptype = (field("sw_part_type") or "").strip().upper()
        ecu = field("ecu_address")
        self.ecu = int(ecu, 16) if ecu else None
        m = re.search(r"\bcall\s*=\s*0x([0-9A-Fa-f]+)", h)
        self.call = int(m.group(1), 16) if m else None
        m = re.search(r"file_checksum\s*=\s*0x([0-9A-Fa-f]+)", h)
        self.file_checksum = int(m.group(1), 16) if m else None
        m = re.search(r"data_format_identifier\s*=\s*0x([0-9A-Fa-f]+)", h)
        self.dfi = int(m.group(1), 16) if m else None

        self.erase = []
        m = re.search(r"erase\s*=\s*\{(.*?)\}\s*;", h, re.S)
        if m:
            nums = [int(x, 16) for x in
                    re.findall(r"0x([0-9A-Fa-f]+)", m.group(1))]
            self.erase = list(zip(nums[0::2], nums[1::2]))

        # block walk: the start offset whose walk consumes the file EXACTLY
        self.blocks = None
        for ds in range(he, he + 8):
            off, blocks, ok = ds, [], True
            while off < len(raw):
                if off + 8 > len(raw):
                    ok = False
                    break
                addr, ln = struct.unpack_from(">II", raw, off)
                if ln == 0 or off + 8 + ln + 2 > len(raw):
                    ok = False
                    break
                crc = struct.unpack_from(">H", raw, off + 8 + ln)[0]
                blocks.append(dict(start=addr, length=ln,
                                   data=raw[off + 8:off + 8 + ln], crc=crc))
                off += 8 + ln + 2
            if ok and off == len(raw) and blocks:
                self.data_start, self.blocks = ds, blocks
                break
        if self.blocks is None:
            raise ValueError(f"{path}: no block walk consumes the file to EOF")

    def check(self):
        """Return a list of integrity problems (empty == good)."""
        p = []
        for i, b in enumerate(self.blocks):
            c = binascii.crc_hqx(b["data"], 0xFFFF)
            if c != b["crc"]:
                p.append(f"block {i} @0x{b['start']:08X}: "
                         f"CRC-16 stored {b['crc']:#06x} != calc {c:#06x}")
        if self.file_checksum is not None:
            c = zlib.crc32(self.raw[self.data_start:]) & 0xFFFFFFFF
            if c != self.file_checksum:
                p.append(f"file CRC-32 stored {self.file_checksum:#010x} "
                         f"!= calc {c:#010x}")
        return p

    def total_payload(self):
        return sum(b["length"] for b in self.blocks)

    def sha256(self):
        """SHA-256 of the whole VBF file (as on disk)."""
        return hashlib.sha256(self.raw).hexdigest()

    def describe(self):
        o = [f"=== {os.path.basename(self.path)}  ({len(self.raw)} bytes)",
             f"   sha256           {self.sha256()}",
             f"   sw_part_number   {self.part}",
             f"   sw_part_type     {self.ptype}",
             f"   ecu_address      "
             + (f"0x{self.ecu:03X}" if self.ecu is not None else "?")]
        if self.file_checksum is not None:
            o.append(f"   file_checksum    0x{self.file_checksum:08X}")
        if self.call is not None:
            o.append(f"   call             0x{self.call:08X}")
        o.append(f"   erase regions    {len(self.erase)}")
        for a, l in self.erase:
            o.append(f"        0x{a:08X} len 0x{l:06X} ({human(l)})")
        o.append(f"   data blocks      {len(self.blocks)}")
        for i, b in enumerate(self.blocks):
            o.append(f"        blk{i} load=0x{b['start']:08X} "
                     f"len=0x{b['length']:06X} ({human(b['length'])}) "
                     f"crc16=0x{b['crc']:04X}")
        o.append(f"   total payload    {human(self.total_payload())}")
        return "\n".join(o)


# --------------------------------------------------------------------------
# transport
# --------------------------------------------------------------------------
def iface_is_up(iface):
    try:
        with open(f"/sys/class/net/{iface}/flags") as f:
            return bool(int(f.read().strip(), 16) & 0x1)
    except OSError:
        return None  # unknown (e.g. vcan quirk) — let send() surface it


def open_isotp(iface, txid, rxid):
    """ISO-TP socket with TX+RX padding to DLC=8 (Ford ECUs ignore short DLC)."""
    s = socket.socket(socket.AF_CAN, socket.SOCK_DGRAM, CAN_ISOTP)
    s.setsockopt(SOL_CAN_ISOTP, CAN_ISOTP_OPTS,
                 struct.pack("=IIBBBB",
                             CAN_ISOTP_TX_PADDING | CAN_ISOTP_RX_PADDING,
                             0, 0, 0, 0, 0))
    s.bind((iface, rxid, txid))
    return s


class Ecu:
    """UDS over ISO-TP. responsePending is a CONTINUE; the wait ends only on
    pending_timeout seconds of TOTAL SILENCE (the clock restarts on each 0x78).
    """

    def __init__(self, iface, txid, rxid, execute=False, logfile=None):
        self.iface, self.txid, self.rxid = iface, txid, rxid
        self.execute = execute
        self.logfile = logfile
        self.sent = []
        self.s = open_isotp(iface, txid, rxid) if execute else None

    def _log(self, line):
        if self.logfile:
            self.logfile.write(line + "\n")
            self.logfile.flush()

    def req(self, hexstr, timeout=5.0, pending_timeout=30.0, what=""):
        hexstr = hexstr.replace(" ", "").upper()
        self.sent.append(hexstr)
        self._log(f"{time.strftime('%H:%M:%S')} -> {hexstr}"
                  + (f"   ({what})" if what else ""))
        if not self.execute:
            return None
        self.s.send(bytes.fromhex(hexstr))
        pend = 0
        # First response is bounded by `timeout`. Only AFTER the ECU says
        # 0x78 responsePending do we extend the budget to `pending_timeout`
        # (and each pending restarts that clock). Otherwise a silent/asleep
        # module would make EVERY request block for the full pending_timeout.
        self.s.settimeout(timeout)
        while True:
            try:
                r = self.s.recv(4096)
            except socket.timeout:
                self._log(f"{time.strftime('%H:%M:%S')} <- <timeout after "
                          f"{pend} pending>")
                return None
            except OSError as e:
                self._log(f"{time.strftime('%H:%M:%S')} <- OSError {e.errno}")
                raise
            if len(r) >= 3 and r[0] == 0x7F and r[2] == 0x78:
                pend += 1
                self._log(f"{time.strftime('%H:%M:%S')} <- responsePending "
                          f"#{pend}")
                self.s.settimeout(pending_timeout)   # extend; clock restarts
                continue
            if len(r) >= 3 and r[0] == 0x7F and r[2] == 0x21:
                time.sleep(0.05)
                self.s.send(bytes.fromhex(hexstr))
                self.s.settimeout(timeout)
                continue
            self._log(f"{time.strftime('%H:%M:%S')} <- {fmt(r)}")
            return r

    def wake(self, tries=8, timeout=0.5, what="wake"):
        """Poke a possibly-asleep bus with 3E 00 until a module answers.

        A sleeping CAN bus commonly drops the first few frames while the
        transceivers wake, so retry with a SHORT per-attempt timeout rather
        than one long blocking read. Returns the response (any) or None after
        `tries` attempts. Never raises — a non-answer here is not fatal; the
        real 10 02 that follows is the true test.
        """
        if not self.execute:
            self._log(f"{time.strftime('%H:%M:%S')} -> 3E00 ({what} x{tries})")
            return None
        for i in range(1, tries + 1):
            r = self.req("3E00", timeout=timeout, pending_timeout=timeout,
                         what=f"{what} {i}/{tries}")
            if r is not None:
                return r
            time.sleep(0.05)
        return None

    def expect(self, hexstr, want_sid, what, **kw):
        r = self.req(hexstr, what=what, **kw)
        if not self.execute:
            return None
        ok = r is not None and len(r) and r[0] == want_sid
        print("   %-4s %-28s %s" % ("OK" if ok else "FAIL", what, fmt(r)))
        if not ok:
            raise SystemExit(f"aborted at {what}: {fmt(r)}")
        return r

    def read_did(self, did, timeout=3.0):
        """Return the decoded string value of a 22 <DID> read, or None."""
        r = self.req("22" + did, timeout=timeout, what="22 " + did)
        if r and r[0] == 0x62:
            return r[3:].decode("latin-1", "replace").rstrip("\x00 ")
        return None

    def read_dtcs(self, status_mask=0xFF, timeout=20.0):
        """UDS 19 02 reportDTCByStatusMask. Returns (dtcs, avail_mask).

        dtcs is a list of (dtc_3byte_int, status_byte). A positive response is
        `59 02 <availabilityMask> [ <b2 b1 b0 status> ... ]`.

        NOTE the generous default timeout: a full DTC dump can be >1 KB and
        many ECUs pace their consecutive frames ~30 ms apart regardless of the
        STmin we request, so a big response (e.g. a PCM with ~290 DTCs = 1171
        bytes) takes >5 s to reassemble. A tight 5 s window made the kernel
        time out mid-reassembly and looked like 'module silent'.
        """
        r = self.req("1902%02X" % status_mask, timeout=timeout,
                     what="19 02 reportDTCByStatusMask")
        if not (r and r[0] == 0x59 and len(r) >= 3):
            return None, None
        avail = r[2]
        body = r[3:]
        dtcs = []
        for i in range(0, len(body) - 3, 4):
            dtc = (body[i] << 16) | (body[i + 1] << 8) | body[i + 2]
            dtcs.append((dtc, body[i + 3]))
        return dtcs, avail

    def read_dtc_count(self, status_mask=0xFF, timeout=5.0):
        """UDS 19 01 reportNumberOfDTCByStatusMask. Returns count or None."""
        r = self.req("1901%02X" % status_mask, timeout=timeout,
                     what="19 01 reportNumberOfDTCByStatusMask")
        # 59 01 <availMask> <fmt> <countHi countLo>
        if r and r[0] == 0x59 and len(r) >= 6:
            return (r[4] << 8) | r[5]
        return None

    def clear_dtcs(self, group=0xFFFFFF, timeout=8.0):
        """UDS 14 ClearDiagnosticInformation for a 3-byte group (default all).
        Returns True on the 0x54 positive response."""
        payload = "14%06X" % (group & 0xFFFFFF)
        r = self.req(payload, timeout=timeout,
                     what="14 clearDiagnosticInformation")
        return bool(r and r[0] == 0x54)

    def reset(self, mode=0x01, timeout=8.0):
        """UDS 11 ECUReset. mode 0x01 = hardReset (default), 0x03 = soft.
        Returns True on the 0x51 positive response."""
        r = self.req("11%02X" % mode, timeout=timeout,
                     what="11 %02X ECUReset" % mode)
        return bool(r and r[0] == 0x51)


def functional_broadcast(iface, payloads, can_id=0x7DF, repeat=1,
                         gap=0.02, log=None):
    """Send functionally-addressed UDS requests to EVERY module at once on the
    broadcast ID (default 0x7DF), as single frames padded to DLC=8.

    Responses are NOT collected: a functional request is answered by every
    module simultaneously and a single raw socket cannot reliably pair them.
    This is fire-and-forget, exactly like the flasher's --quiet-bus arming.
    `payloads` is a list of byte sequences, e.g. [[0x14,0xFF,0xFF,0xFF]].
    """
    sock = _raw_can(iface)
    try:
        for payload in payloads:
            for _ in range(repeat):
                sock.send(_frame(can_id, _single(payload)))
                if log:
                    log.write(f"{time.strftime('%H:%M:%S')} ~> {can_id:03X}#"
                              f"{bytes(_single(payload)).hex().upper()}\n")
                    log.flush()
                time.sleep(gap)
    finally:
        sock.close()


# --------------------------------------------------------------------------
# functional bus quiet + broadcast TesterPresent (ported from bcmflash.py)
# --------------------------------------------------------------------------
def _raw_can(iface):
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind((iface,))
    return s


def _frame(can_id, payload):
    data = bytes(payload)
    return struct.pack("=IB3x8s", can_id, 8, data.ljust(8, b"\x00"))


def _single(payload):
    p = bytes(payload)
    return bytes([len(p)]) + p


class BusQuiet:
    """Silence other modules with functional 7DF#02 10 82 (programmingSession),
    undone with 7DF#02 11 81 (functional hardReset). UNCONFIRMED at runtime —
    the response is suppressed. Off by default. Ported verbatim in behaviour
    from the vehicle-validated BCM implementation.
    """
    ARM_REPEAT = 20

    def __init__(self, iface, can_id=0x7DF, execute=False, enabled=False):
        self.iface, self.can_id = iface, can_id
        self.execute, self.enabled = execute, enabled
        self.armed = False
        self.sock = None

    def _raw(self, data):
        if not self.execute:
            return
        if self.sock is None:
            self.sock = _raw_can(self.iface)
        self.sock.send(_frame(self.can_id, _single(data)))

    def arm(self):
        if not self.enabled:
            return self
        print(f"   quiet-bus: {self.can_id:03X}#02 10 82 x{self.ARM_REPEAT} "
              "(functional programmingSession, NO confirmation)")
        for _ in range(self.ARM_REPEAT):
            self._raw([0x10, 0x82])
            time.sleep(0.02)
        self.armed = True
        return self

    def restore(self):
        if not (self.enabled and self.armed):
            return
        print(f"   quiet-bus restore: {self.can_id:03X}#02 11 81 "
              "(functional hardReset, ALL modules)")
        try:
            for _ in range(3):
                self._raw([0x11, 0x81])
                time.sleep(0.05)
        except Exception as e:  # noqa: BLE001
            print(f"   !! quiet-bus restore FAILED: {e}; S3 timeout will free "
                  "the modules in ~5 s")
        self.armed = False
        if self.sock:
            self.sock.close()
            self.sock = None


class Keepalive:
    """Periodic TesterPresent 3E 80. On the physical ISO-TP socket by default;
    pass can_id (e.g. 0x7DF) for a broadcast frame on a separate raw socket.
    """
    def __init__(self, ecu, period=1.5, can_id=None):
        self.ecu, self.period, self.can_id = ecu, period, can_id
        self.sent = 0
        self._stop = threading.Event()
        self._t = None
        self._raw = None

    def start(self):
        if not self.ecu.execute or self.period <= 0:
            return self
        if self.can_id is not None:
            self._raw = _raw_can(self.ecu.iface)

        def run():
            while not self._stop.wait(self.period):
                try:
                    if self._raw is not None:
                        self._raw.send(_frame(self.can_id, _single([0x3E, 0x80])))
                    else:
                        self.ecu.s.send(bytes.fromhex("3E80"))
                    self.sent += 1
                except OSError:
                    return
        self._t = threading.Thread(target=run, daemon=True)
        self._t.start()
        return self

    def stop(self):
        self._stop.set()
        if self._t:
            self._t.join(timeout=self.period + 1.0)
            self._t = None
        if self._raw:
            self._raw.close()
            self._raw = None


# --------------------------------------------------------------------------
# download stage: 34 RequestDownload -> 36 TransferData (chunked) -> 37 exit
# --------------------------------------------------------------------------
def download_blocks(ecu, blocks, tag, progress_interval=2.0):
    total = sum(b["length"] for b in blocks)
    done = 0
    t0 = time.time()
    for bi, b in enumerate(blocks):
        rd = ("340044" + struct.pack(">I", b["start"]).hex()
              + struct.pack(">I", b["length"]).hex())
        r = ecu.expect(rd, 0x74, f"{tag} blk{bi} 34 RequestDownload",
                       timeout=10.0)
        # maxNumberOfBlockLength is DECLARED by the ECU in the 0x74 response.
        chunk = 0x80
        if ecu.execute and r is not None and len(r) >= 3:
            if r[1] == 0x20 and len(r) >= 4:
                chunk = ((r[2] << 8) | r[3]) - 2
            elif r[1] == 0x10:
                chunk = r[2] - 2
            if chunk <= 0:
                raise SystemExit(f"nonsensical maxNumberOfBlockLength {r.hex()}")
            print(f"      ECU declares {chunk + 2} -> {chunk} payload B/transfer")
        bc, off = 1, 0
        t_last = time.time()
        while off < b["length"]:
            piece = b["data"][off:off + chunk]
            if ecu.execute:
                rr = ecu.req((bytes([0x36, bc & 0xFF]) + piece).hex(),
                             timeout=10.0)
                if rr is None or rr[0] != 0x76:
                    raise SystemExit(f"{tag} TransferData blk{bi} bc={bc}: "
                                     f"{fmt(rr)}")
            off += len(piece)
            done += len(piece)
            bc = (bc + 1) & 0xFF
            now = time.time()
            # report at least every `progress_interval` seconds, and on the
            # final transfer of the block
            if ecu.execute and (now - t_last >= progress_interval
                                or off >= b["length"]):
                t_last = now
                el = now - t0
                pct = 100.0 * done / total if total else 100.0
                print("\r      %s %5.1f%%  %s/%s  %.1f KiB/s   "
                      % (tag, pct, human(done), human(total),
                         (done / el / 1024) if el else 0), end="", flush=True)
        if ecu.execute:
            print()
        ecu.expect("37", 0x77, f"{tag} blk{bi} 37 TransferExit", timeout=15.0)


# --------------------------------------------------------------------------
# generic raw memory read / write (used by the memread / memwrite commands).
# The SBL must already be loaded and running; these are the exact services the
# UCDS PSCM EEPROM capture used: 35 RequestUpload and 34/FF00/0304 for write.
# --------------------------------------------------------------------------
def upload_block(ecu, addr, length, addr_len_fmt=0x44, progress_interval=2.0,
                 tag="read"):
    """35 RequestUpload -> 36 TransferData(read) x N -> 37 TransferExit.

    Returns the uploaded bytes. The ECU declares maxNumberOfBlockLength in its
    0x75 response; each 0x36 reply carries SID+bc then <chunk> payload bytes.
    """
    rq = ("35%02X" % addr_len_fmt + struct.pack(">I", addr).hex()
          + struct.pack(">I", length).hex())
    r = ecu.expect(rq, 0x75, f"{tag} 35 RequestUpload @0x{addr:08X}",
                   timeout=10.0)
    chunk = 0x80
    if ecu.execute and r is not None and len(r) >= 3:
        if r[1] == 0x20 and len(r) >= 4:
            chunk = ((r[2] << 8) | r[3]) - 2
        elif r[1] == 0x10:
            chunk = r[2] - 2
        if chunk <= 0:
            raise SystemExit(f"nonsensical maxNumberOfBlockLength {r.hex()}")
        print(f"      ECU declares {chunk + 2} -> {chunk} payload B/transfer")
    out = bytearray()
    bc = 1
    t0 = t_last = time.time()
    while len(out) < length:
        rr = ecu.req("36%02X" % (bc & 0xFF), timeout=10.0)
        if rr is None or rr[0] != 0x76:
            raise SystemExit(f"{tag} TransferData(read) bc={bc}: {fmt(rr)}")
        # 76 <bc> <payload...>
        out += rr[2:]
        bc = (bc + 1) & 0xFF
        now = time.time()
        if ecu.execute and (now - t_last >= progress_interval
                            or len(out) >= length):
            t_last = now
            el = now - t0
            pct = 100.0 * len(out) / length if length else 100.0
            print("\r      %s %5.1f%%  %s/%s  %.1f KiB/s   "
                  % (tag, pct, human(min(len(out), length)), human(length),
                     (len(out) / el / 1024) if el else 0), end="", flush=True)
    if ecu.execute:
        print()
    ecu.expect("37", 0x77, f"{tag} 37 TransferExit", timeout=15.0)
    return bytes(out[:length])


def download_raw_block(ecu, addr, data, addr_len_fmt=0x44,
                       progress_interval=2.0, tag="write"):
    """34 RequestDownload -> 36 TransferData x N -> 37 TransferExit for a raw
    (addr, bytes) region. Mirrors download_blocks but for a single arbitrary
    memory block rather than a VBF block table."""
    length = len(data)
    rq = ("34%02X" % addr_len_fmt + struct.pack(">I", addr).hex()
          + struct.pack(">I", length).hex())
    r = ecu.expect(rq, 0x74, f"{tag} 34 RequestDownload @0x{addr:08X}",
                   timeout=10.0)
    chunk = 0x80
    if ecu.execute and r is not None and len(r) >= 3:
        if r[1] == 0x20 and len(r) >= 4:
            chunk = ((r[2] << 8) | r[3]) - 2
        elif r[1] == 0x10:
            chunk = r[2] - 2
        if chunk <= 0:
            raise SystemExit(f"nonsensical maxNumberOfBlockLength {r.hex()}")
        print(f"      ECU declares {chunk + 2} -> {chunk} payload B/transfer")
    bc, off = 1, 0
    t0 = t_last = time.time()
    while off < length:
        piece = data[off:off + chunk]
        if ecu.execute:
            rr = ecu.req((bytes([0x36, bc & 0xFF]) + piece).hex(), timeout=10.0)
            if rr is None or rr[0] != 0x76:
                raise SystemExit(f"{tag} TransferData bc={bc}: {fmt(rr)}")
        off += len(piece)
        bc = (bc + 1) & 0xFF
        now = time.time()
        if ecu.execute and (now - t_last >= progress_interval or off >= length):
            t_last = now
            el = now - t0
            pct = 100.0 * off / length if length else 100.0
            print("\r      %s %5.1f%%  %s/%s  %.1f KiB/s   "
                  % (tag, pct, human(off), human(length),
                     (off / el / 1024) if el else 0), end="", flush=True)
    if ecu.execute:
        print()
    ecu.expect("37", 0x77, f"{tag} 37 TransferExit", timeout=15.0,
               pending_timeout=30.0)


def erase_region(ecu, addr, length, erase_timeout=60.0, tag="erase"):
    """31 01 FF00 <addr><len> eraseMemory (Ford standard routine FF00)."""
    ecu.expect("3101FF00" + struct.pack(">I", addr).hex()
               + struct.pack(">I", length).hex(), 0x71,
               f"{tag} 31 01 FF00 @0x{addr:08X}", timeout=15.0,
               pending_timeout=erase_timeout)


def verify_routine(ecu, erase_timeout=60.0):
    """31 01 0304 checkMemory / finalise routine."""
    ecu.expect("31010304", 0x71, "31 01 0304 checkMemory", timeout=15.0,
               pending_timeout=erase_timeout)
