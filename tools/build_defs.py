#!/usr/bin/env python3
"""Build defs/vbflasher_defs.sqlite — the module-definition database the
VBFlasher GUI uses to decode and edit DIDs (Direct Configuration) and the
512-byte Central Car Configuration (CCC).

Source: the IDSdb build tree (~/Projects/ford/IDSdb/build). The output is a
small, self-contained, source-agnostic format: a module definition is one set
of DIDs with decoded field layouts, matched to a live module either by its
Part II specification (DID F110) or by (vehicle model, model year, CAN
address). Where a definition came from (FDRS MDX, IDS MDX, IDS ffdata/CCF
synthesis, UCDS, module firmware) is kept only as an informational `origin` string.
Firmware-derived specs: DEFAULT_FW_SPECS (e.g. ../HCM/hcm_did_defs.json).

Not copied on purpose: part-number lists, security bytes, DTC failure
metadata, provenance columns. Run again whenever IDSdb is rebuilt:

    python3 tools/build_defs.py [--idsdb ~/Projects/ford/IDSdb/build]
                                [--ucds-ipc ~/Projects/ford/IPC/RE/config/ipc_did_defs.json]
                                [--ucds-bcm ~/Projects/ford/BCM/Research/docs/ucds]
                                [--ucds-ipma ~/Projects/ford/IPMA/Research/ucds]
"""
import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
DEFAULT_IDSDB = Path.home() / "Projects/ford/IDSdb/build"
DEFAULT_UCDS_IPC = Path.home() / "Projects/ford/IPC/RE/config/ipc_did_defs.json"
DEFAULT_UCDS_BCM = Path.home() / "Projects/ford/BCM/Research/docs/ucds"
DEFAULT_UCDS_IPMA = Path.home() / "Projects/ford/IPMA/Research/ucds"
OUT = HERE / "defs" / "vbflasher_defs.sqlite"

SCHEMA = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
-- one decoded DID layout, shared by every definition that uses it
CREATE TABLE layout(
    id INTEGER PRIMARY KEY, sha TEXT UNIQUE, name TEXT, size INTEGER,
    did_type TEXT, fields BLOB            -- zlib(JSON list of fields)
);
-- a DID set (many model-year documents are identical: stored once)
CREATE TABLE didset(id INTEGER PRIMARY KEY, sha TEXT UNIQUE, n INTEGER);
CREATE TABLE didset_item(
    set_id INTEGER, did INTEGER, layout_id INTEGER,
    rd TEXT,          -- read sessions, e.g. '01 03'  ('' = any / unknown)
    wr TEXT,          -- write sessions; NULL = not writable
    wr_sec TEXT       -- Ford security level for writing (N -> 27 2N-1); NULL = none
);
CREATE INDEX didset_item_set ON didset_item(set_id);
-- a module definition
CREATE TABLE module_def(
    id INTEGER PRIMARY KEY,
    kind TEXT,        -- 'spec' (match F110) | 'vehicle' (match model/year/address)
    spec TEXT,        -- normalised Part II spec, e.g. DS1U5T-14G371-EM
    model TEXT, model_year TEXT,
    acronym TEXT, title TEXT,
    address INTEGER,  -- physical request CAN id
    origin TEXT,      -- informational: fdrs | ids | synth | ucds
    priority INTEGER, -- lower wins when several definitions match equally
    set_id INTEGER, did_count INTEGER, config_count INTEGER
);
CREATE INDEX module_def_spec ON module_def(spec);
CREATE INDEX module_def_addr ON module_def(address, model);
-- DTC text per module address (base 2-byte DTC, failure type stripped)
CREATE TABLE dtc_text(address INTEGER, code INTEGER, text TEXT,
                      PRIMARY KEY(address, code)) WITHOUT ROWID;
-- Central Car Configuration (CCF) definitions: the 512-byte buffer
CREATE TABLE ccc_def(id INTEGER PRIMARY KEY, name TEXT UNIQUE, model TEXT,
                     model_year TEXT, car_config TEXT, length INTEGER,
                     modules TEXT);
CREATE TABLE ccc_block(ccc_id INTEGER, block_no INTEGER, offset INTEGER,
                       length INTEGER, layout_id INTEGER);
"""

SKIP_UNITS = {"Undefined / Not Used", "", None}


def norm_spec(pn):
    """'DS-1U5T-14G371-EM' / 'DS1U5T-14G371-EM' -> 'DS1U5T-14G371-EM'."""
    if not pn:
        return None
    s = pn.strip().upper().rstrip("\x00 ")
    if s.startswith("DS-"):
        s = "DS" + s[3:]
    return s


def to_int(v):
    if v is None:
        return None
    if isinstance(v, int):
        return v
    s = str(v).strip()
    try:
        return int(s, 0)
    except ValueError:
        try:
            return int(s, 16)
        except ValueError:
            return None


def sessions(s):
    if not s:
        return ""
    return " ".join(x.replace("session_", "").upper() for x in s.split())


def parse_access(js):
    rd, wr, sec = "", None, None
    if not js:
        return rd, wr, sec
    try:
        a = json.loads(js)
    except ValueError:
        return rd, wr, sec
    r = a.get("readable")
    if r:
        rd = sessions(r.get("sessions"))
    w = a.get("writeable")
    if w and (w.get("services") or "").upper().endswith("2E"):
        wr = sessions(w.get("sessions"))
        s = w.get("security")
        if s:
            m = re.search(r"(\d+)", s)
            sec = m.group(1) if m else s
    return rd, wr, sec


TYPE_MAP = {"enumerated": "enum", "unsigned": "uint", "signed": "sint",
            "bytes": "bytes", "ascii": "ascii", "bcd": "bcd", "DTC": "dtc"}


def num(v):
    """'1/20' / '0.2' / '-40' -> float, else None."""
    if v is None:
        return None
    s = str(v).strip()
    try:
        if "/" in s:
            a, b = s.split("/", 1)
            return float(a) / float(b)
        return float(s)
    except (ValueError, ZeroDivisionError):
        return None


def mdx_field(sf, origin="fdrs"):
    """Normalise one MDX subfield (lsb/msb count from the LSB of the WHOLE
    payload). Returns None for header-only nodes without a bit span.

    Scaling is stored as physical = raw * r + o. FDRS MDX already uses that
    form (AM presets: 530 kHz + raw*10). IDS ffdata (origin 'synth') stores the
    converter's field_offset in RAW counts, physical = (raw + offset) * res:
    V_BATT_BCM res 1/20 offset 120 -> 6.0..18.75 V, HBC#1 2/1 offset -128 ->
    symmetric current. So the synth offset is converted to offset*res here.
    """
    lsb, msb = to_int(sf.get("lsb")), to_int(sf.get("msb"))
    if lsb is None or msb is None or msb < lsb:
        return None
    code = (sf.get("name") or "").strip()
    nice = (sf.get("ids_mnemonic") or "").strip()
    if origin == "synth" and nice and nice != code:
        name, key = nice, code            # readable text, ffdata mnemonic as key
    else:
        name, key = code or sf.get("id") or "?", None
    f = {"n": name, "l": lsb, "m": msb,
         "t": TYPE_MAP.get(sf.get("data_type"), "uint" if msb - lsb < 64 else "bytes")}
    if key:
        f["k"] = key
    if sf.get("enum"):
        e = []
        for o in sf["enum"]:
            v = to_int(o.get("value"))
            if v is None:
                continue
            e.append([v, (o.get("description") or o.get("name") or "").strip()])
        if e:
            f["e"] = e
            f["t"] = "enum"
    u = sf.get("units")
    if u not in SKIP_UNITS:
        f["u"] = u
    res = num(sf.get("resolution"))
    off = num(sf.get("offset"))
    if res is not None and res != 1.0:
        f["r"] = res
    if off:
        f["o"] = off * (res if (origin == "synth" and res is not None) else 1.0)
    d = sf.get("description")
    if d and isinstance(d, str) and d.strip() and d.strip() not in (f["n"], code):
        f["d"] = d.strip()[:300]
    return f


def pick_subfields(subs):
    """ffdata synth lists a parameter once per operation (read encoding and
    write/IO-control encoding). For decoding keep the read alternatives when
    any exist, then drop exact duplicates."""
    if any(s.get("ids_operation") == "read" for s in subs):
        subs = [s for s in subs if s.get("ids_operation") in (None, "read")]
    seen, out = set(), []
    for s in subs:
        k = (s.get("name"), s.get("lsb"), s.get("msb"))
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
    return out


class Writer:
    def __init__(self, out):
        if out.exists():
            out.unlink()
        out.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(out)
        self.db.executescript(SCHEMA)
        self.layouts = {}
        self.sets = {}
        self.nfields = {}          # layout id -> field count
        self.supp = []             # (address, model prefix, {did: (lid, wr, sec)}, tag)

    def layout(self, name, size, did_type, fields):
        blob = json.dumps(fields, separators=(",", ":"), ensure_ascii=False)
        sha = hashlib.sha1(f"{name}\x00{size}\x00{did_type}\x00{blob}".encode()).hexdigest()
        lid = self.layouts.get(sha)
        if lid is None:
            cur = self.db.execute(
                "INSERT INTO layout(sha,name,size,did_type,fields) VALUES(?,?,?,?,?)",
                (sha, name, size, did_type, zlib.compress(blob.encode(), 9)))
            lid = self.layouts[sha] = cur.lastrowid
            self.nfields[lid] = len(fields)
        return lid

    def didset(self, items):
        items = sorted(set(items), key=lambda x: (x[0], x[1]))
        sha = hashlib.sha1(json.dumps(items).encode()).hexdigest()
        sid = self.sets.get(sha)
        if sid is None:
            cur = self.db.execute("INSERT INTO didset(sha,n) VALUES(?,?)", (sha, len(items)))
            sid = self.sets[sha] = cur.lastrowid
            self.db.executemany(
                "INSERT INTO didset_item(set_id,did,layout_id,rd,wr,wr_sec) VALUES(?,?,?,?,?,?)",
                [(sid,) + it for it in items])
        return sid, len(items), sum(1 for it in items if it[3] is not None)

    def merge_supp(self, address, model, origin, items):
        """Fold UCDS-extracted DIDs into a vehicle definition of the same
        module/vehicle family. A UCDS layout with fields replaces an IDS layout
        for the same DID (it is the real tool's decode for this generation);
        the IDS access (sessions/security) is kept when it has one. With
        `force` the UCDS access always wins, and any UCDS layout with fields
        replaces the IDS one (the catalogue was checked against this module)."""
        for addr, prefix, dids, tag, force in self.supp:
            if addr != address or not (model or "").startswith(prefix):
                continue
            items = list(items)
            for did, (lid, wr, sec) in dids.items():
                olds = [it for it in items if it[0] == did]
                if not olds:
                    items.append((did, lid, "", wr, sec))
                    continue
                old = olds[0]
                if force:
                    nf = self.nfields.get(lid, 0)
                    keep = old[1] if nf == 0 and self.nfields.get(old[1], 0) else lid
                    items = [it for it in items if it[0] != did]
                    items.append((did, keep, old[2], wr, sec))
                    continue
                if self.nfields.get(lid, 0) >= max(1, self.nfields.get(old[1], 0)):
                    items = [it for it in items if it[0] != did]
                    items.append((did, lid, old[2], old[3] if old[3] is not None else wr,
                                  old[4] if old[3] is not None else sec))
            if tag not in origin:
                origin = f"{origin}+{tag}"
        return origin, items

    def module(self, kind, spec, model, year, acronym, title, address, origin,
               priority, items):
        if kind == "vehicle" and self.supp:
            origin, items = self.merge_supp(address, model, origin, items)
        if not items:
            return None
        sid, n, ncfg = self.didset(items)
        cur = self.db.execute(
            "INSERT INTO module_def(kind,spec,model,model_year,acronym,title,address,"
            "origin,priority,set_id,did_count,config_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (kind, spec, model, year, acronym, title, address, origin, priority,
             sid, n, ncfg))
        return cur.lastrowid


def did_items(w, rows, origin="fdrs"):
    """rows: (number, name, byte_size, did_type, access, subfields)."""
    items = []
    for number, name, size, did_type, access, subfields in rows:
        did = to_int(number)
        if did is None or not 0 <= did <= 0xFFFF:
            continue
        size = to_int(size)
        fields = []
        if subfields:
            try:
                subs = json.loads(subfields)
            except ValueError:
                subs = []
            # IDS ffdata 'mcp' encodings are As-Built (Module Configuration
            # Programming) block fields: their "address" is the as-built block
            # number (0x0001, 0x0002 ...), NOT a UDS DID. Never present them
            # as DIDs.
            if subs and all(s.get("ids_operation") == "mcp" for s in subs):
                continue
            subs = [s for s in subs if s.get("ids_operation") != "mcp"]
            try:
                for sf in pick_subfields(subs):
                    f = mdx_field(sf, origin)
                    if f is not None:
                        if size and f["m"] >= size * 8:
                            continue
                        fields.append(f)
            except ValueError:
                pass
        name = (name or "").strip()
        if origin == "synth" and fields:
            # synth names are a mnemonic (V_BATT_BCM) or "N ffdata parameter(s)
            # at 0x...": use the readable field text instead
            texts = list(dict.fromkeys(f["n"] for f in fields))
            if len(texts) == 1:
                name = texts[0]
            elif re.match(r"^\d+ ffdata parameter", name):
                name = "; ".join(texts[:3]) + (f" (+{len(texts) - 3})" if len(texts) > 3 else "")
        lid = w.layout(name or f"DID {did:04X}", size, did_type, fields)
        rd, wr, sec = parse_access(access)
        items.append((did, lid, rd, wr, sec))
    return items


def build_mdx(w, mdx):
    c = sqlite3.connect(f"file:{mdx}?mode=ro", uri=True)
    q_did = ("SELECT d.number,d.name,d.byte_size,d.did_type,d.access,d.subfields "
             "FROM did_edge e JOIN did_detail d ON d.id=e.detail_id WHERE e.file_id=?")
    n = 0
    # 1) FDRS MDX: one document per Part II spec (F110)
    for fid, pn, short, ename, phys in c.execute(
            "SELECT f.id,f.part_number,e.shortname,e.ecu_name,e.physical_address "
            "FROM file f JOIN ecu e ON e.file_id=f.id WHERE f.source='fdrs' AND f.parsed=1 "
            "ORDER BY f.part_number, f.id").fetchall():
        spec = norm_spec(pn)
        if not spec:
            continue
        items = did_items(w, c.execute(q_did, (fid,)))
        if w.module("spec", spec, None, None, short, ename, to_int(phys), "fdrs", 0, items):
            n += 1
    print(f"   fdrs spec definitions: {n}")
    # 2) IDS per-platform MDX (mostly hand-made stubs) -> address via transport
    tmap = {}
    for plat, mtype, tgt in c.execute(
            "SELECT f.platform, t.module_type, t.can_target FROM transport t "
            "JOIN file f ON f.id=t.file_id WHERE t.can_target IS NOT NULL"):
        tmap.setdefault((plat, mtype), to_int(tgt))
    n = 0
    for fid, plat, mod in c.execute(
            "SELECT id,platform,module FROM file WHERE source='ids' AND parsed=1").fetchall():
        addr = tmap.get((plat, mod))
        if addr is None:
            continue
        items = did_items(w, c.execute(q_did, (fid,)))
        if w.module("vehicle", None, plat, None, mod, f"{mod} ({plat})", addr, "ids", 3, items):
            n += 1
    print(f"   ids platform definitions: {n}")
    # 3) IDS ffdata+CCF synthesis: one document per (model, MY, module)
    n = 0
    t0 = time.time()
    for fid, model, year, mod, addr in c.execute(
            "SELECT file_id,model,model_year,module,request_address FROM synth_context "
            "WHERE kind='module' ORDER BY model, model_year, module").fetchall():
        a = to_int(addr)
        if a is None:
            continue
        items = did_items(w, c.execute(q_did, (fid,)), "synth")
        if w.module("vehicle", None, model, year, mod, f"{mod} ({model} {year})", a,
                    "synth", 2, items):
            n += 1
    print(f"   synth vehicle definitions: {n}  ({time.time() - t0:.0f}s)")
    # 4) DTC text per address (spec docs first, then synth module docs)
    rows = {}
    for addr, num, desc in c.execute(
            "SELECT e2.physical_address, d.number, d.description FROM dtc_edge e "
            "JOIN dtc_detail d ON d.id=e.detail_id JOIN ecu e2 ON e2.file_id=e.file_id "
            "JOIN file f ON f.id=e.file_id WHERE f.source='fdrs'"):
        a, code = to_int(addr), to_int(num)
        if a is not None and code is not None and desc:
            rows.setdefault((a, code & 0xFFFF), desc.strip())
    for addr, num, desc in c.execute(
            "SELECT s.request_address, d.number, d.description FROM synth_context s "
            "JOIN dtc_edge e ON e.file_id=s.file_id JOIN dtc_detail d ON d.id=e.detail_id "
            "WHERE s.kind='module'"):
        a, code = to_int(addr), to_int(num)
        if a is not None and code is not None and desc:
            rows.setdefault((a, code & 0xFFFF), desc.strip())
    w.db.executemany("INSERT INTO dtc_text VALUES(?,?,?)",
                     [(a, code, t) for (a, code), t in rows.items()])
    print(f"   dtc texts: {len(rows)}")


def ccf_fields(c, block_pk, total_bytes):
    total = total_bytes * 8
    fields = []
    for ppk, name, title, ptype, byte_off, bstart, bstop, width in c.execute(
            "SELECT p.id, p.name, g.title, p.ptype, p.byte_offset, p.bit_start, p.bit_stop, p.width "
            "FROM ccf_param p JOIN ccf_group g ON g.id=p.group_id WHERE g.block_id=? "
            "ORDER BY p.byte_offset, p.bit_start", (block_pk,)).fetchall():
        if bstart is None or bstop is None or byte_off is None:
            continue
        start = byte_off * 8 + bstart % 8          # MSB-first, block-absolute
        stop = start + (bstop - bstart)
        if stop >= total:
            continue
        f = {"n": (title or name or "?").strip(), "l": total - 1 - stop,
             "m": total - 1 - start, "k": name}
        pt = (ptype or "").upper()
        opts = c.execute("SELECT value,code,text,name FROM ccf_option WHERE param_id=? "
                         "ORDER BY id", (ppk,)).fetchall()
        if opts:
            e = []
            for v, code, text, oname in opts:
                iv = to_int(v)
                if iv is None:
                    continue
                label = (text or oname or "").strip()
                if code:
                    label = f"{label} [{code.strip()}]"
                e.append([iv, label])
            f["t"] = "enum"
            f["e"] = e
        elif pt == "ASCII":
            f["t"] = "ascii"
        elif pt == "BCD":
            f["t"] = "bcd"
        else:
            f["t"] = "uint" if (stop - start) < 64 else "bytes"
        fields.append(f)
    return fields


def build_ccc(w, ccfdb):
    c = sqlite3.connect(f"file:{ccfdb}?mode=ro", uri=True)
    n = 0
    for fid, fname, car_cfg in c.execute(
            "SELECT id,name,car_config FROM ccf_file WHERE name NOT LIKE '%SYNTH%' "
            "ORDER BY name").fetchall():
        blocks = c.execute(
            "SELECT b.id, b.block_id, b.name, a.start_address, a.length, a.models, a.years "
            "FROM ccf_block b JOIN ccf_address a ON a.block_id=b.id "
            "WHERE b.file_id=? AND a.module='AS_BUILT' AND upper(b.parameter_id) IN ('0XF105','0XF106') "
            "ORDER BY a.start_address", (fid,)).fetchall()
        if not blocks:
            continue
        base = blocks[0][3]
        model = blocks[0][5]
        year = blocks[0][6]
        mods = sorted({m for (m,) in c.execute(
            "SELECT DISTINCT a.module FROM ccf_address a JOIN ccf_block b ON b.id=a.block_id "
            "WHERE b.file_id=? AND a.module!='AS_BUILT' AND upper(b.parameter_id) IN ('0XF105','0XF106')",
            (fid,))})
        end = max(b[3] + b[4] for b in blocks)
        cur = w.db.execute(
            "INSERT INTO ccc_def(name,model,model_year,car_config,length,modules) VALUES(?,?,?,?,?,?)",
            (fname, model, year, car_cfg, end - base, ",".join(mods)))
        cid = cur.lastrowid
        seen = set()
        for bpk, bno, bname, start, length, _, _ in blocks:
            if bpk in seen:
                continue
            seen.add(bpk)
            fields = ccf_fields(c, bpk, length)
            lid = w.layout(f"CCC block {bno}", length, "ccc", fields)
            w.db.execute("INSERT INTO ccc_block VALUES(?,?,?,?,?)",
                         (cid, to_int(bno), start - base, length, lid))
        n += 1
    print(f"   central config definitions: {n}")


def _ucds_fields(raw, size):
    fields = []
    for f in raw:
        if f.get("bit_start") is None or f.get("bit_end") is None:
            continue
        lo, hi = sorted((int(f["bit_start"]), int(f["bit_end"])))
        if size and hi >= size * 8:
            continue
        ff = {"n": f.get("name") or "?", "l": lo, "m": hi,
              "t": f.get("type") or ("enum" if f.get("enum") else "uint")}
        if f.get("enum"):
            ff["e"] = [[int(v), str(t)] for v, t in f["enum"]]
        if f.get("unit") not in SKIP_UNITS:
            ff["u"] = f["unit"]
        mul, div = f.get("mul") or 1, f.get("div") or 1
        if mul != 1 or div != 1:
            ff["r"] = mul / div
        fields.append(ff)
    return fields


def load_ucds_ipc(w, path):
    """C520 IPC DIDs extracted from UCDS process RAM (the 'KUGA 2 / Escape
    [C520] 2017-2019 - IPC LEVEL3' list). Bit numbers count from the payload
    LSB, as in MDX."""
    if not path or not Path(path).exists():
        print("   ucds ipc: skipped (file not found)")
        return
    d = json.load(open(path))
    dids = {}
    for did_hex, fl in d.items():
        did = to_int("0x" + did_hex)
        if did is None:
            continue
        size = next((to_int(f.get("byte_size")) for f in fl if f.get("byte_size")), None)
        name = next((f.get("name") for f in fl if f.get("bit_start") is None
                     and f.get("name")), None)
        fields = _ucds_fields(fl, size)
        if size is None and fields:
            size = (max(f["m"] for f in fields) + 8) // 8
        lid = w.layout(name or f"DID {did:04X}", size, "ucds", fields)
        wr = "03" if did_hex.upper().startswith("DE") else None
        dids[did] = (lid, wr, "2" if wr else None)       # Ford level 2 = 27 03
    w.supp.append((0x720, "C520", dids, "ucds", False))
    print(f"   ucds ipc DIDs: {len(dids)}")


def load_ucds_dir(w, folder, address, label, wr_sec=None):
    """DIDs decoded from UCDS process RAM (UCDS/work/ram extract_did.py or
    defs_only.py): one did_<DID>_decoded.json / did_<DID>_defs.json per DID
    page opened in UCDS, plus catalogue names (BCM) for DIDs whose fields were
    not extracted. All extractions are C520 Kuga. `wr_sec` = Ford security
    level for config writes (2 -> 27 03)."""
    folder = Path(folder) if folder else None
    if not folder or not folder.is_dir():
        print(f"   ucds {label}: skipped (folder not found)")
        return
    names = {}
    cat = folder / "bcm_did_catalog.json"
    if cat.exists():
        for k, v in json.load(open(cat)).get("catalog", {}).items():
            names[to_int("0x" + k)] = v.get("name")
    inv = folder / "DID_INVENTORY.md"          # "Confirmed catalogue labels" table
    if inv.exists():
        for m in re.finditer(r"^\| `([0-9A-F]{4})` \| #\d+ \| ([^|]+?) \|", inv.read_text(),
                             re.M):
            names.setdefault(int(m.group(1), 16), m.group(2).strip())
    dc = folder / "bcm_direct_config.json"     # names for decoded tables too
    if dc.exists():
        for k, e in json.load(open(dc))["dids"].items():
            names.setdefault(to_int("0x" + k), e["name"])
    dids = {}
    for fn in sorted(list(folder.glob("*_decoded.json")) + list(folder.glob("did_*_defs.json"))):
        d = json.load(open(fn))
        if d.get("name"):
            names.setdefault(to_int("0x" + d["did"]), d["name"])
        did = to_int("0x" + d["did"]) if d.get("did") else (
            0xDE00 if fn.name.lower().startswith("de00") else None)
        if did is None:
            continue
        size = d.get("blob_len") or d.get("byte_size") or (
            len(d.get("blob_hex") or "") // 2 or None)
        fields = _ucds_fields(d.get("params") or [], size)
        lid = w.layout(names.get(did) or f"DID {did:04X}", size, "ucds", fields)
        wr = "03" if 0xDE00 <= did <= 0xDEFF else None
        dids[did] = (lid, wr, wr_sec if wr else None)
    # BCM catalogue (BCM/Research docs/ucds/tools/direct_config_json.py): every
    # DID UCDS reads or lists under Direct Configuration, with an access class.
    # Its access is authoritative for this module: "config" DIDs are written
    # like UCDS writes DE00 (10 03 + 27 03), everything else is read-only.
    force = False
    if dc.exists():
        j = json.load(open(dc))
        sess, lvl = j["write"]["session"], j["write"]["security_level"]
        for k, e in j["dids"].items():
            did = to_int("0x" + k)
            wr, sec = (sess, lvl) if e["access"] == "config" else (None, None)
            if did in dids:                  # decoded table: keep its fields
                dids[did] = (dids[did][0], wr, sec)
                continue
            names[did] = e["name"]
            fields = _ucds_fields(e["fields"], e["size"])
            dids[did] = (w.layout(e["name"], e["size"], "ucds", fields), wr, sec)
        force = True
    for did, name in names.items():
        if did is not None and did not in dids and name:
            dids[did] = (w.layout(name, None, "ucds", []), None, None)
    w.supp.append((address, "C520", dids, "ucds", force))
    print(f"   ucds {label} DIDs: {len(dids)} "
          f"({sum(1 for v in dids.values() if w.nfields.get(v[0]))} with fields)")


MDXCACHE_TYPES = {"enum": "enum", "unsigned": "uint", "signed": "sint", "ascii": "ascii",
                  "bcd": "bcd", "bytes": "bytes"}


def load_mdx_cache_spec(w, path):
    """A module definition decoded from an FDRS client-cache MDX (binary ETIS
    serialisation) by IPMA/EyeQ3/tools/mdx_cache_decode.py + ipma_report.py.
    Registered as a 'spec' definition (matched on F110), priority 1 because its
    fields were cross-checked 197/197 against UCDS RAM extractions."""
    if not path or not Path(path).exists():
        print(f"   mdx-cache spec: skipped ({path} not found)")
        return
    j = json.load(open(path))
    units, dtypes = ({int(k): v for k, v in j["units"].items()},
                     {int(k): v for k, v in j["dtypes"].items()})
    items = []
    for did_hex, d in sorted(j["dids"].items()):
        did = int(did_hex, 16)
        size = d.get("byte_size")
        fields = []
        for f in d["fields"]:
            t = MDXCACHE_TYPES.get(dtypes.get(f.get("dtype")), "uint")
            ff = {"n": f["name"], "l": f["lsb"], "m": f["msb"], "t": t}
            if f.get("enum"):
                ff["e"] = [[int(v), str(lab)] for v, lab in f["enum"]]
            if t in ("uint", "sint"):
                num, den = f.get("num") or 1, f.get("den") or 1
                if (num, den) != (1, 1):
                    ff["r"] = num / den
                if f.get("offset"):
                    ff["o"] = f["offset"]          # physical = raw * r + o
                u = units.get(f.get("unit_ord"))
                if u:
                    ff["u"] = u
            fields.append(ff)
        lid = w.layout(d.get("name") or f"DID {did:04X}", size, "mdxcache", fields)
        cfg = 0xDE00 <= did <= 0xDEFF
        # config DIDs: 2E in extended session; MDX security level 03 -> Ford level 2 (27 03)
        items.append((did, lid, "", "03" if cfg else None, "2" if cfg else None))
    w.module("spec", j["spec"], None, None, "IPMA", "IPMA (Delphi RH850 + EyeQ3, CGEA)",
             j["address"], "fdrs-cache+ucds", 1, items)
    rows = []
    for code_hex, e in j.get("dtcs", {}).items():
        rows.append((j["address"], int(code_hex, 16), e["name"]))
    w.db.executemany("INSERT OR IGNORE INTO dtc_text VALUES(?,?,?)", rows)
    print(f"   mdx-cache spec {j['spec']}: {len(items)} DIDs, {len(rows)} DTC texts")


DEFAULT_MDXCACHE = [Path.home() / "Projects/ford/IPMA/EyeQ3/ucds/ipma_cgea_defs.json"]


def load_firmware_spec(w, path):
    """A module definition reconstructed from the module's OWN firmware DID
    table and handlers, checked against a bench read (e.g. ../HCM/
    hcm_did_defs.json, generated by HCM/work/make_hcm_did_defs.py). Fields are
    already in the defs JSON shape (n/l/m/t/e/u/r/o/d). Registered as a 'spec'
    definition matched on F110, priority 1: no IDS/FDRS document exists for
    that spec, and the firmware table is the exact set the module serves."""
    if not path or not Path(path).exists():
        print(f"   firmware spec: skipped ({path} not found)")
        return
    j = json.load(open(path))
    rd = j.get("read_sessions", "")
    items = []
    for did_hex, d in sorted(j["dids"].items()):
        lid = w.layout(d["name"], d["size"], "firmware", d["fields"])
        items.append((int(did_hex, 16), lid, rd, d.get("wr"), d.get("wr_sec")))
    w.module("spec", j["spec"], None, None, j["acronym"], j["title"],
             j["address"], j.get("origin", "firmware"), 1, items)
    print(f"   firmware spec {j['spec']}: {len(items)} DIDs")


DEFAULT_FW_SPECS = [Path.home() / "Projects/ford/HCM/hcm_did_defs.json"]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--idsdb", default=str(DEFAULT_IDSDB))
    ap.add_argument("--ucds-ipc", default=str(DEFAULT_UCDS_IPC))
    ap.add_argument("--ucds-bcm", default=str(DEFAULT_UCDS_BCM))
    ap.add_argument("--ucds-ipma", default=str(DEFAULT_UCDS_IPMA))
    ap.add_argument("-o", "--out", default=str(OUT))
    a = ap.parse_args()
    src = Path(a.idsdb).expanduser()
    out = Path(a.out)
    tmp = out.with_suffix(".tmp")
    w = Writer(tmp)
    t0 = time.time()
    print(f"building {out} from {src}")
    # UCDS extractions are loaded first and folded into every IDS vehicle
    # definition of the same address + vehicle family while those are built
    load_ucds_ipc(w, Path(a.ucds_ipc).expanduser())
    load_ucds_dir(w, Path(a.ucds_bcm).expanduser(), 0x726, "bcm")
    # IPMA needs SecurityAccess 27 03 (Ford level 2) for its config DIDs,
    # even to read them (ecu_db: IPMA level-3 secret, UCDS capture)
    load_ucds_dir(w, Path(a.ucds_ipma).expanduser(), 0x706, "ipma", wr_sec="2")
    build_mdx(w, src / "mdx_data.sqlite")
    build_ccc(w, src / "ccf.sqlite")
    for p in DEFAULT_MDXCACHE:
        load_mdx_cache_spec(w, p)
    for p in DEFAULT_FW_SPECS:
        load_firmware_spec(w, p)
    w.db.executemany("INSERT INTO meta VALUES(?,?)", [
        ("format", "1"),
        ("built", time.strftime("%Y-%m-%d %H:%M:%S")),
        ("source", "IDSdb mdx_data.sqlite + ccf.sqlite + UCDS C520 IPC/BCM/IPMA extractions + FDRS-cache CGEA IPMA (DSNK3T-19H406-AA) + HCM firmware DID table (DS7S71-13K031-CA)"),
        ("bits", "field l/m = lsb/msb counted from the LSB of the whole payload"),
    ])
    w.db.commit()
    w.db.execute("VACUUM")
    w.db.close()
    os.replace(tmp, out)
    print(f"layouts {len(w.layouts)}, did sets {len(w.sets)}; "
          f"{out.stat().st_size / 1e6:.1f} MB in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    sys.exit(main())
