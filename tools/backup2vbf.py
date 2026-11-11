#!/usr/bin/env python3
"""Rebuild flashable VBFs from a `vbflasher backup` directory, using OEM VBFs
as the layout template.

The OEM file provides the header (kept byte-for-byte except the file_checksum
digits, which are rewritten in place at the same width and case), the part
number, the erase map and the block layout. The DATA comes from the backup
image of the module. Two layouts:

  --layout oem    (default) the template's own blocks: same addresses, same
                  lengths. When the module runs that exact part this must
                  reproduce the OEM file byte-for-byte, and the tool reports so.
  --layout erase  the template's blocks (unchanged), PLUS one extra block per
                  non-blank span of the ERASE map that no OEM block covers.
                  This restores everything the erase wipes, including data the
                  OEM file does not carry (e.g. EyeQ3 runtime records inside
                  the app erase range). 0xFF runs >= --min-gap are not sent
                  (erased flash already reads 0xFF); extra-span bounds are
                  aligned outward to --align, never into an OEM block. Not
                  written when there is nothing extra.

Refuses: compressed (dfi 0x10) or signed (sw_signature) templates, a template
whose part number is not among the backup's ident DIDs (wrong software, so the
layout may not match; --force overrides), and any byte the backup does not hold
or holds only as "unstable" (blank_noise majority vote).

    python3 tools/backup2vbf.py BACKUP_DIR OEM.vbf [OEM2.vbf ...] -o OUT_DIR
    python3 tools/backup2vbf.py BACKUP_DIR N1BT-14F397-BA.vbf --layout erase \\
        -o OUT_DIR --suffix _full
"""
import argparse
import binascii
import hashlib
import json
import os
import re
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from vbf import Vbf  # noqa: E402

SW_DIDS = ("F188", "F120", "F124", "F125", "F108", "F10A")


class Backup:
    """The backup's regions as one sparse, read-only address space."""

    def __init__(self, d):
        self.dir = d
        self.m = json.load(open(os.path.join(d, "manifest.json")))
        self.regions = []
        for r in self.m["regions"]:
            data = open(os.path.join(d, r["file"]), "rb").read()
            if len(data) != r["length"]:
                raise SystemExit(f"{r['file']}: {len(data)} bytes, manifest says {r['length']}")
            if hashlib.sha256(data).hexdigest() != r["sha256"]:
                raise SystemExit(f"{r['file']}: sha256 differs from manifest")
            mask = None
            if r.get("unstable_mask"):
                mask = open(os.path.join(d, r["unstable_mask"]), "rb").read()
            self.regions.append((int(r["addr"], 16), data, mask, r["name"]))
        self.regions.sort()

    def read(self, addr, n):
        """Bytes [addr, addr+n); may span adjacent regions; refuses gaps and
        unstable bytes."""
        out = bytearray()
        a = addr
        while len(out) < n:
            for base, data, mask, name in self.regions:
                if base <= a < base + len(data):
                    off = a - base
                    take = min(n - len(out), len(data) - off)
                    if mask is not None and any(mask[off:off + take]):
                        raise SystemExit(
                            f"0x{a:08X}+0x{take:X} in '{name}' contains unstable "
                            "(blank-noise) bytes; refusing to put them in a VBF")
                    out += data[off:off + take]
                    a += take
                    break
            else:
                raise SystemExit(f"backup does not hold 0x{a:08X} "
                                 f"(needed for 0x{addr:08X}+0x{n:X})")
        return bytes(out)


def ff_spans(data, base, min_gap, align):
    """(addr, bytes) spans of `data` without its 0xFF runs >= min_gap (and
    without leading/trailing 0xFF of any length), bounds aligned outward to
    `align` on ABSOLUTE addresses. All-0xFF -> []."""
    n = len(data)
    cuts = [(m.start(), m.end()) for m in
            re.finditer(rb"\xff{%d,}" % max(1, min_gap), data)]
    lead = n - len(data.lstrip(b"\xff"))
    trail = n - len(data.rstrip(b"\xff"))
    if lead == n:
        return []
    cuts = [(0, lead)] + cuts + [(n - trail, n)]
    spans, pos = [], 0
    for cs, ce in sorted(cuts):
        if cs > pos:
            spans.append([pos, cs])
        pos = max(pos, ce)
    out = []
    for s, e in spans:
        s = max(((base + s) // align) * align - base, 0)
        e = min(-(-(base + e) // align) * align - base, n)
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return [(base + s, data[s:e]) for s, e in out]


def build(tpl, bk, layout, min_gap, align):
    if tpl.dfi not in (None, 0):
        raise SystemExit(f"{tpl.path}: compressed template (dfi 0x{tpl.dfi:02X}) not supported")
    if re.search(r"\bsw_signature\s*=", tpl.header_code):
        raise SystemExit(f"{tpl.path}: signed VBF (sw_signature) cannot be rebuilt")
    if layout == "oem":
        blocks = [(b["start"], bk.read(b["start"], b["length"])) for b in tpl.blocks]
    else:
        # The OEM blocks verbatim (from the backup), PLUS every non-blank span
        # of the erase map that no OEM block covers -- i.e. the data a flash
        # of the OEM file would erase and not put back. The OEM blocks are not
        # split or re-aligned: only the extra spans are new on the wire.
        if not tpl.erase:
            raise SystemExit(f"{tpl.path}: no erase map, --layout erase is meaningless")
        blocks = [(b["start"], bk.read(b["start"], b["length"])) for b in tpl.blocks]
        oem = sorted((b["start"], b["start"] + b["length"]) for b in tpl.blocks)
        for a, n in tpl.erase:
            img = bytearray(bk.read(a, n))
            for os_, oe in oem:                    # hide what the OEM file covers
                s0, e0 = max(os_, a), min(oe, a + n)
                if s0 < e0:
                    img[s0 - a:e0 - a] = b"\xff" * (e0 - s0)
            for sa, sd in ff_spans(bytes(img), a, min_gap, align):
                se = sa + len(sd)
                for os_, oe in oem:                # alignment must not grow
                    if sa < oe <= se and os_ < sa:  # a span into an OEM block
                        sa = oe
                    if sa <= os_ < se:
                        se = os_
                if se > sa:
                    blocks.append((sa, bk.read(sa, se - sa)))
        blocks.sort()
    # every block must lie inside the UNION of the erase regions (an OEM
    # calibration block spans three contiguous regions)
    union = []
    for ea, en in sorted(tpl.erase):
        if union and ea <= union[-1][1]:
            union[-1][1] = max(union[-1][1], ea + en)
        else:
            union.append([ea, ea + en])
    for a, d in blocks:
        if tpl.erase and not any(us <= a and a + len(d) <= ue for us, ue in union):
            raise SystemExit(f"block 0x{a:08X}+0x{len(d):X} leaves the erase map")
    body = b"".join(struct.pack(">II", a, len(d)) + d
                    + struct.pack(">H", binascii.crc_hqx(d, 0xFFFF))
                    for a, d in blocks)
    # header verbatim; only the file_checksum digits change, same width/case
    hdr = tpl.raw[:tpl.data_start]
    m = list(re.finditer(r"file_checksum\s*=\s*0x([0-9A-Fa-f]+)", tpl.header_code))
    if len(m) != 1:
        raise SystemExit(f"{tpl.path}: expected one live file_checksum, found {len(m)}")
    s, e = m[0].span(1)
    old = tpl.header_text[s:e]
    new = "%0*x" % (len(old), zlib.crc32(body))
    if any(c.isupper() for c in old):
        new = new.upper()
    hdr = hdr[:s] + new.encode() + hdr[e:]
    return hdr + body, blocks


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("backup")
    ap.add_argument("templates", nargs="+", metavar="OEM.vbf")
    ap.add_argument("-o", "--outdir", required=True)
    ap.add_argument("--layout", choices=("oem", "erase"), default="oem")
    ap.add_argument("--suffix", default="", help="appended to the output file stem")
    ap.add_argument("--min-gap", type=lambda x: int(x, 0), default=0x1000)
    ap.add_argument("--align", type=lambda x: int(x, 0), default=0x100)
    ap.add_argument("--force", action="store_true",
                    help="build even if the part is not what the module reported")
    a = ap.parse_args()
    bk = Backup(a.backup)
    ident = bk.m.get("ident", {})
    live = {ident.get(d) for d in SW_DIDS if ident.get(d)}
    os.makedirs(a.outdir, exist_ok=True)
    rc = 0
    for t in a.templates:
        tpl = Vbf(t)
        print(f"== {tpl.part} ({tpl.ptype})  template {t}")
        if tpl.part not in live:
            msg = (f"module reported {sorted(live)}, not {tpl.part}: the OEM block layout "
                   "may not describe what is on the module")
            if not a.force:
                print(f"   REFUSED: {msg} (--force to override)")
                rc = 1
                continue
            print(f"   WARNING (--force): {msg}")
        raw, blocks = build(tpl, bk, a.layout, a.min_gap, a.align)
        if a.layout == "erase" and len(blocks) == len(tpl.blocks):
            print("   nothing in the erase map beyond the OEM blocks: the OEM-layout "
                  "file already restores this part completely; not written")
            continue
        out = os.path.join(a.outdir, f"{tpl.part}{a.suffix}.vbf")
        with open(out, "wb") as fh:
            fh.write(raw)
        chk = Vbf(out)
        problems = chk.check()
        for b in chk.blocks:
            print(f"   blk 0x{b['start']:08X} len 0x{b['length']:08X} crc16 0x{b['crc']:04X}")
        same = raw == tpl.raw
        print(f"   -> {out}  {len(raw)} B  sha256 {hashlib.sha256(raw).hexdigest()[:16]}..")
        print(f"   container: {'OK' if not problems else '; '.join(problems)}   "
              f"{'BYTE-IDENTICAL to the OEM file' if same else 'differs from the OEM file'}")
        if not same:
            oem = {b["start"]: b["data"] for b in tpl.blocks}
            extra = sum(len(d) for _, d in blocks) - sum(len(d) for d in oem.values())
            for b0, d0 in oem.items():
                d1 = bk.read(b0, len(d0))
                n = sum(x != y for x, y in zip(d0, d1))
                print(f"   OEM blk 0x{b0:08X}: {'module == OEM' if n == 0 else f'{n} bytes differ on the module'}")
            print(f"   payload {'+' if extra >= 0 else ''}{extra} B vs the OEM file")
        rc |= bool(problems)
    return rc


if __name__ == "__main__":
    sys.exit(main())
