#!/usr/bin/env python3
"""Module definitions for the VBFlasher GUI: find the right DID layouts for a
live module, decode/encode DID payloads field by field, and handle the
512-byte Central Car Configuration (CCC) image.

Data lives in defs/vbflasher_defs.sqlite (built by tools/build_defs.py from
IDSdb). Field bit positions `l`/`m` count from the LSB of the WHOLE payload
(the MDX convention), so a field's value is (int(payload) >> l) & mask.

Also reads/writes the UCDS file formats used for config backups:
  * Direct Configuration XML  <DirectConfiguration><VEHICLE MODULE=..><DID ID="DE00">hex</DID>
  * As-Built XML              <AS_BUILT_DATA><VEHICLE><CCC_MODULE><CCC_DATA>hex(512)</CCC_DATA>
"""
import json
import re
import sqlite3
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent
DEFS_DB = HERE / "defs" / "vbflasher_defs.sqlite"


# --------------------------------------------------------------------------
# field codec
# --------------------------------------------------------------------------
@dataclass
class Field:
    name: str
    lsb: int
    msb: int
    type: str = "uint"                  # enum uint sint bytes ascii bcd dtc
    enum: list = field(default_factory=list)   # [[value, label], ...]
    units: Optional[str] = None
    res: Optional[float] = None
    off: Optional[float] = None
    desc: Optional[str] = None
    key: Optional[str] = None           # CCF parameter name, when known

    @classmethod
    def from_json(cls, d):
        return cls(d.get("n", "?"), d["l"], d["m"], d.get("t", "uint"),
                   d.get("e") or [], d.get("u"), d.get("r"), d.get("o"),
                   d.get("d"), d.get("k"))

    @property
    def width(self):
        return self.msb - self.lsb + 1

    def fits(self, size):
        return size is not None and self.msb < size * 8

    def byte_span(self, size):
        """(first_byte, end_byte) when byte aligned, else None."""
        if self.lsb % 8 or self.width % 8:
            return None
        first = (size * 8 - 1 - self.msb) // 8
        return first, first + self.width // 8

    def position(self, size):
        """Human position 'B3.7-B3.4' (byte 0 first, bit 7 = MSB)."""
        if not size:
            return f"bits {self.lsb}..{self.msb}"
        hb, hbit = (size * 8 - 1 - self.msb) // 8, self.msb % 8
        lb, lbit = (size * 8 - 1 - self.lsb) // 8, self.lsb % 8
        if (hb, hbit) == (lb, lbit):
            return f"B{hb}.{hbit}"
        if hbit == 7 and lbit == 0:
            return f"B{hb}" if hb == lb else f"B{hb}-B{lb}"
        return f"B{hb}.{hbit}-B{lb}.{lbit}"

    # raw integer value -------------------------------------------------
    def get_raw(self, payload: bytes) -> int:
        n = int.from_bytes(payload, "big")
        return (n >> self.lsb) & ((1 << self.width) - 1)

    def set_raw(self, payload: bytes, value: int) -> bytes:
        if value < 0 or value >> self.width:
            raise ValueError(f"{self.name}: {value} does not fit {self.width} bit(s)")
        n = int.from_bytes(payload, "big")
        mask = ((1 << self.width) - 1) << self.lsb
        n = (n & ~mask) | (value << self.lsb)
        return n.to_bytes(len(payload), "big")

    def get_bytes(self, payload):
        span = self.byte_span(len(payload))
        if span:
            return payload[span[0]:span[1]]
        return self.get_raw(payload).to_bytes((self.width + 7) // 8, "big")

    def set_bytes(self, payload, data):
        span = self.byte_span(len(payload))
        need = (self.width + 7) // 8
        data = bytes(data[:need]).ljust(need, b"\x00")
        if span:
            return payload[:span[0]] + data + payload[span[1]:]
        return self.set_raw(payload, int.from_bytes(data, "big"))

    # display -----------------------------------------------------------
    def label(self, raw):
        for v, lab in self.enum:
            if v == raw:
                return lab
        return None

    def display(self, payload: bytes) -> str:
        if not self.fits(len(payload)):
            return "<outside payload>"
        if self.type == "ascii":
            b = self.get_bytes(payload)
            return "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in b)
        if self.type in ("bytes", "dtc") or self.width > 64:
            return self.get_bytes(payload).hex(" ").upper()
        raw = self.get_raw(payload)
        if self.enum:
            lab = self.label(raw)
            return f"{lab}" if lab is not None else f"0x{raw:X} (undefined)"
        if self.type == "bcd":
            return f"{raw:X}"
        if self.type == "sint" and raw >> (self.width - 1):
            raw -= 1 << self.width
        if self.res or self.off:
            v = raw * (self.res or 1.0) + (self.off or 0.0)
            s = f"{v:g}"
        else:
            s = str(raw)
        return f"{s} {self.units}" if self.units else s

    def is_editable_scalar(self):
        return self.type not in ("ascii", "bytes", "dtc") and self.width <= 64


@dataclass
class DidDef:
    did: int
    name: str
    size: Optional[int]
    did_type: Optional[str]
    fields: list
    rd: str = ""
    wr: Optional[str] = None
    wr_sec: Optional[str] = None

    @property
    def writable(self):
        return self.wr is not None

    @property
    def is_config(self):
        return self.writable and 0xDE00 <= self.did <= 0xDEFF


@dataclass
class ModuleDef:
    id: int
    kind: str
    spec: Optional[str]
    model: Optional[str]
    model_year: Optional[str]
    acronym: Optional[str]
    title: Optional[str]
    address: Optional[int]
    origin: str
    priority: int
    did_count: int
    config_count: int
    match: str = ""           # why it was proposed

    def label(self):
        who = self.spec or " ".join(x for x in (self.model, self.model_year) if x)
        return (f"{self.acronym or '?'} — {who}  [{self.origin}, "
                f"{self.did_count} DIDs / {self.config_count} writable]"
                + (f"  ({self.match})" if self.match else ""))


def norm_spec(pn):
    if not pn:
        return None
    s = pn.strip().upper().rstrip("\x00 .")
    if s.startswith("DS-"):
        s = "DS" + s[3:]
    return s or None


def spec_family(spec):
    """'DS1U5T-14G371-EM' -> ('DS1U5T-14G371', 'EM')."""
    m = re.match(r"^(.*)-([A-Z]{1,3})$", spec or "")
    return (m.group(1), m.group(2)) if m else (spec, "")


def _suffix_rank(s):
    v = 0
    for ch in s:
        v = v * 27 + (ord(ch) - 64)
    return v


class Defs:
    def __init__(self, path=DEFS_DB):
        self.path = Path(path)
        self.ok = self.path.exists()
        self.db = (sqlite3.connect(f"file:{self.path}?mode=ro", uri=True,
                                   check_same_thread=False) if self.ok else None)
        self._layout_cache = {}

    def meta(self):
        if not self.ok:
            return {}
        return dict(self.db.execute("SELECT key,value FROM meta"))

    def _mods(self, where, args, match=""):
        if not self.ok:
            return []
        rows = self.db.execute(
            "SELECT id,kind,spec,model,model_year,acronym,title,address,origin,priority,"
            "did_count,config_count FROM module_def WHERE " + where, args).fetchall()
        return [ModuleDef(*r, match=match) for r in rows]

    # -- matching -----------------------------------------------------------
    def candidates(self, address=None, f110=None, model=None, year=None):
        """Ranked definitions for a live module. Exact F110 spec first, then
        same-spec-family siblings (nearest suffix), then vehicle
        (model/year/address) definitions, then same-address leftovers."""
        out, seen = [], set()

        def add(lst):
            for m in lst:
                if m.id not in seen:
                    seen.add(m.id)
                    out.append(m)

        spec = norm_spec(f110)
        if spec:
            add(self._mods("spec=? ORDER BY priority, did_count DESC", (spec,),
                           "exact F110 spec"))
            fam, suf = spec_family(spec)
            if fam:
                sib = self._mods("spec LIKE ? ORDER BY spec", (fam + "-%",))
                want = _suffix_rank(suf)
                sib.sort(key=lambda m: abs(_suffix_rank(spec_family(m.spec)[1]) - want))
                for m in sib:
                    m.match = f"sibling spec of {spec} (verify!)"
                add(sib)
        if address is not None:
            if model:
                veh = []
                if year:
                    veh += self._mods("address=? AND model=? AND model_year=? "
                                      "ORDER BY priority, did_count DESC",
                                      (address, model, year), f"{model} {year}")
                veh += self._mods("address=? AND model=? ORDER BY priority, model_year DESC",
                                  (address, model), f"{model}, other MY")
                base = model.split("_")[0]
                veh += self._mods("address=? AND model LIKE ? ORDER BY priority, model, "
                                  "model_year DESC", (address, base + "%"), f"{base} family")
                # a hand-verified source (ucds, priority 1) beats an ffdata
                # synthesis for the same vehicle family; otherwise keep tier order
                order = {id(m): i for i, m in enumerate(veh)}
                veh.sort(key=lambda m: (m.priority > 1, order[id(m)]))
                add(veh)
            add(self._mods("address=? AND kind='spec' ORDER BY spec DESC", (address,),
                           "same address"))
        return out

    def search(self, text, address=None, limit=400):
        like = f"%{text.strip()}%"
        where = "(spec LIKE ? OR model LIKE ? OR acronym LIKE ? OR title LIKE ?)"
        args = [like] * 4
        if address is not None:
            where += " AND address=?"
            args.append(address)
        return self._mods(where + " ORDER BY address, model, model_year, spec LIMIT ?",
                          tuple(args) + (limit,))

    def models(self, address=None):
        if not self.ok:
            return []
        if address is None:
            q = "SELECT DISTINCT model FROM module_def WHERE model IS NOT NULL ORDER BY 1"
            return [r[0] for r in self.db.execute(q)]
        return [r[0] for r in self.db.execute(
            "SELECT DISTINCT model FROM module_def WHERE model IS NOT NULL AND address=? "
            "ORDER BY 1", (address,))]

    def years(self, model):
        if not self.ok:
            return []
        ys = {r[0] for r in self.db.execute(
            "SELECT DISTINCT model_year FROM module_def WHERE model=?", (model,)) if r[0]}
        ys |= {r[0] for r in self.db.execute(
            "SELECT DISTINCT model_year FROM ccc_def WHERE model=?", (model,)) if r[0]}
        return sorted(ys)

    # -- layouts ------------------------------------------------------------
    def _layout(self, lid):
        hit = self._layout_cache.get(lid)
        if hit is None:
            name, size, did_type, blob = self.db.execute(
                "SELECT name,size,did_type,fields FROM layout WHERE id=?", (lid,)).fetchone()
            fl = [Field.from_json(d) for d in json.loads(zlib.decompress(blob))]
            hit = self._layout_cache[lid] = (name, size, did_type, fl)
        return hit

    def dids(self, module_def_id):
        """{did: DidDef} for one definition."""
        (sid,) = self.db.execute("SELECT set_id FROM module_def WHERE id=?",
                                 (module_def_id,)).fetchone()
        out = {}
        for did, lid, rd, wr, sec in self.db.execute(
                "SELECT did,layout_id,rd,wr,wr_sec FROM didset_item WHERE set_id=? ORDER BY did",
                (sid,)):
            name, size, did_type, fl = self._layout(lid)
            if did in out:          # several blocks behind one DID: keep the first
                continue
            out[did] = DidDef(did, name, size, did_type, fl, rd or "", wr, sec)
        return out

    def dtc_text(self, address, dtc3):
        if not self.ok:
            return None
        r = self.db.execute("SELECT text FROM dtc_text WHERE address=? AND code=?",
                            (address, (dtc3 >> 8) & 0xFFFF)).fetchone()
        return r[0] if r else None

    # -- central config -----------------------------------------------------
    def ccc_defs(self):
        if not self.ok:
            return []
        return self.db.execute("SELECT id,name,model,model_year,car_config,length,modules "
                               "FROM ccc_def ORDER BY name").fetchall()

    def ccc_blocks(self, ccc_id):
        out = []
        for bno, off, length, lid in self.db.execute(
                "SELECT block_no,offset,length,layout_id FROM ccc_block WHERE ccc_id=? "
                "ORDER BY offset", (ccc_id,)):
            name, size, _, fl = self._layout(lid)
            out.append(CccBlock(bno, off, length, [ccc_extend_enum(f) for f in fl]))
        return out

    def guess_ccc(self, image: bytes, model=None, year=None):
        """Pick the CCF definition for an image -> (ccc_id, reason).

        The car-configuration document number ('31827371 Rev 05') is the same
        in every CCF file, so it cannot tell platforms apart. The vehicle type
        byte (F106[2], PARAM_EUCD_CCF_VEHICLE_TYPE) can: only the platform's
        own files name its value (0x0A = 'C520' only in C520 files). Among
        those, prefer the vehicle model/year hint (the Module data tab's
        Vehicle), then the definition naming most of the image's enum values,
        then the newest model year."""
        best = []
        for cid, name, mdl, yr, _cc, _len, _mods in self.ccc_defs():
            vt, named, total = None, 0, 0
            for b in self.ccc_blocks(cid):
                p = image[b.offset:b.offset + b.length]
                if len(p) != b.length:
                    continue
                for f in b.fields:
                    if not f.enum or not f.fits(len(p)):
                        continue
                    lab = f.label(f.get_raw(p))
                    total += 1
                    named += lab is not None
                    if f.key == "PARAM_EUCD_CCF_VEHICLE_TYPE":
                        vt = lab
            if vt is None:
                continue
            hint = (2 if model and mdl == model and year and yr == year else
                    1 if model and mdl == model else 0)
            best.append((hint, named / total if total else 0.0, _year_key(yr), cid,
                         f"{name}: vehicle type '{vt}'"
                         + (f", matches {model} {year or ''}".rstrip() if hint else "")
                         + f", {named}/{total} values named"))
        if not best:
            return None, "no definition names this image's vehicle type"
        best.sort(reverse=True)
        return best[0][3], best[0][4]

    def ccc_vehicle_type_ok(self, ccc_id, image: bytes) -> bool:
        for b in self.ccc_blocks(ccc_id):
            p = image[b.offset:b.offset + b.length]
            for f in b.fields:
                if f.key == "PARAM_EUCD_CCF_VEHICLE_TYPE" and f.enum and f.fits(len(p)):
                    return f.label(f.get_raw(p)) is not None
        return False


def _year_key(y):
    m = re.search(r"(\d+(?:\.\d+)?)", y or "")
    return float(m.group(1)) if m else 0.0


@dataclass
class CccBlock:
    no: int
    offset: int
    length: int
    fields: list


CCC_LEN = 512
CCC_CHECKSUM_OFF = 257      # block-4 byte 1: sum of block 5 (258..511) & 0xFF
F106_BASE = 256             # DID F106 byte i = image byte 256 + i (BCM 0x8100 + i)

# Values the module firmware accepts that the platform's IDS CCF does not list
# (IDS lists only the variants Ford shipped on that platform). Keyed by CCF
# parameter name; shown in the editor with a [fw]/[other platform] tag.
CCC_EXTRA_ENUM = {
    "PARAM_EUCD_CCF_DAYRUNNING_LIGHT": [
        (0x06, "Dedicated DRL, user switchable from the cluster menu "
               "[fw: BCM JV6T-14C094, not in any IDS CCF]"),
        (0x0A, "User configurable DTRL lit in auto - dipped beam, only with halogen "
               "headlamps 0x02 [other platform: C344N/C346N/V408N]"),
    ],
}


def ccc_extend_enum(f: Field) -> Field:
    extra = CCC_EXTRA_ENUM.get(f.key or "")
    if not extra or not f.enum:
        return f
    have = {v for v, _ in f.enum}
    add = [[v, lab] for v, lab in extra if v not in have]
    if not add:
        return f
    return Field(f.name, f.lsb, f.msb, f.type, sorted(list(f.enum) + add),
                 f.units, f.res, f.off, f.desc, f.key)


def ccc_checksum(img: bytes) -> int:
    return sum(img[CCC_CHECKSUM_OFF + 1:CCC_LEN]) & 0xFF


def ccc_fix_checksum(img: bytes) -> bytes:
    b = bytearray(img)
    b[CCC_CHECKSUM_OFF] = ccc_checksum(img)
    return bytes(b)


def ccc_check(img: bytes):
    """List of problems ([] = OK). Verified on 3 UCDS as-built files."""
    p = []
    if len(img) != CCC_LEN:
        p.append(f"length {len(img)} != 512")
        return p
    if img[256] != 0xFC:
        p.append(f"block-4 length byte 0x{img[256]:02X} != 0xFC")
    if img[CCC_CHECKSUM_OFF] != ccc_checksum(img):
        p.append(f"checksum 0x{img[CCC_CHECKSUM_OFF]:02X} != computed "
                 f"0x{ccc_checksum(img):02X}")
    return p


# --------------------------------------------------------------------------
# UCDS file formats
# --------------------------------------------------------------------------
def _hex(s):
    return bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", s or ""))


def load_direct_xml(path):
    """-> (attrs dict, {did_int: bytes})"""
    root = ET.parse(path).getroot()
    veh = root.find("VEHICLE")
    if veh is None:
        raise ValueError("not a UCDS Direct Configuration XML (no VEHICLE)")
    dids = {}
    for d in veh.findall("DID"):
        dids[int(d.get("ID"), 16)] = _hex(d.text)
    return dict(veh.attrib), dids


def save_direct_xml(path, module, dids, vin="NONE", vehicle_id="", year=""):
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             "<DirectConfiguration><!--UCDS Direct Configuration XML FILE-->",
             f'\t<VEHICLE MODULE="{module}" VIN="{vin or "NONE"}" '
             f'VEHICLE_ID="{vehicle_id}" VEHICLE_YEAR="{year}">']
    for did in sorted(dids):
        lines.append(f'\t\t<DID ID="{did:04X}">{dids[did].hex().upper()}</DID>')
    lines += ["\t</VEHICLE>", "</DirectConfiguration>"]
    Path(path).write_bytes(("\r\n".join(lines) + "\r\n").encode())


def load_asbuilt_xml(path):
    """-> (vin, indirection address, 512-byte image)"""
    root = ET.parse(path).getroot()
    veh = root.find("VEHICLE")
    data = root.find(".//CCC_DATA")
    if data is None:
        raise ValueError("not a UCDS As-Built XML (no CCC_DATA)")
    vin = (veh.findtext("VIN") or "").strip() if veh is not None else ""
    ind = root.findtext(".//INDIR_ADR")
    return vin, int(ind, 16) if ind else 0x8000, _hex(data.text)


def save_asbuilt_xml(path, image, vin="", indir=0x8000):
    vin = (vin or "").ljust(17)[:17]
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             "<AS_BUILT_DATA><!--UCDS ASBUILT XML FILE-->",
             "\t<VEHICLE>", f"\t\t<VIN>{vin}</VIN>",
             f"\t\t<INDIR_ADR>{indir:08X}</INDIR_ADR>", "\t\t<CCC_MODULE>",
             f"\t\t\t<CCC_DATA>  {image.hex().upper()}</CCC_DATA>",
             "\t\t</CCC_MODULE>", "\t</VEHICLE>", "</AS_BUILT_DATA>"]
    Path(path).write_bytes(("\r\n".join(lines) + "\r\n").encode())
