#!/usr/bin/env python3
"""Build defs/vbflasher_defs.sqlite — the module-definition database the
VBFlasher GUI uses to decode and edit DIDs (Direct Configuration) and the
512-byte Central Car Configuration (CCC).

Source: the IDSdb build tree (~/Projects/ford/IDSdb/build). The output is a
small, self-contained, source-agnostic format: a module definition is one set
of DIDs with decoded field layouts, matched to a live module either by its
Part II specification (DID F110) or by (vehicle model, model year, CAN
address). Where a definition came from (FDRS MDX, IDS MDX, IDS ffdata/CCF
synthesis, UCDS) is kept only as an informational `origin` string.

Not copied on purpose: part-number lists, security bytes, DTC failure
metadata, provenance columns. Run again whenever IDSdb is rebuilt:

    python3 tools/build_defs.py [--idsdb ~/Projects/ford/IDSdb/build]
                                [--ucds-ipc ~/Projects/ford/IPC/RE/config/ipc_did_defs.json]
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


def mdx_field(sf):
    """Normalise one MDX subfield (lsb/msb count from the LSB of the WHOLE
    payload). Returns None for header-only nodes without a bit span."""
    lsb, msb = to_int(sf.get("lsb")), to_int(sf.get("msb"))
    if lsb is None or msb is None or msb < lsb:
        return None
    f = {"n": (sf.get("name") or "").strip() or sf.get("id") or "?",
         "l": lsb, "m": msb,
         "t": TYPE_MAP.get(sf.get("data_type"), "uint" if msb - lsb < 64 else "bytes")}
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
    for k, key, neutral in (("resolution", "r", 1.0), ("offset", "o", 0.0)):
        try:
            fv = float(sf.get(k))
        except (TypeError, ValueError):
            continue
        if fv != neutral:
            f[key] = fv
    d = sf.get("description")
    if d and isinstance(d, str) and d.strip() and d.strip() != f["n"]:
        f["d"] = d.strip()[:300]
    return f


class Writer:
    def __init__(self, out):
        if out.exists():
            out.unlink()
        out.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(out)
        self.db.executescript(SCHEMA)
        self.layouts = {}
        self.sets = {}

    def layout(self, name, size, did_type, fields):
        blob = json.dumps(fields, separators=(",", ":"), ensure_ascii=False)
        sha = hashlib.sha1(f"{name}\x00{size}\x00{did_type}\x00{blob}".encode()).hexdigest()
        lid = self.layouts.get(sha)
        if lid is None:
            cur = self.db.execute(
                "INSERT INTO layout(sha,name,size,did_type,fields) VALUES(?,?,?,?,?)",
                (sha, name, size, did_type, zlib.compress(blob.encode(), 9)))
            lid = self.layouts[sha] = cur.lastrowid
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

    def module(self, kind, spec, model, year, acronym, title, address, origin,
               priority, items):
        if not items:
            return None
        sid, n, ncfg = self.didset(items)
        cur = self.db.execute(
            "INSERT INTO module_def(kind,spec,model,model_year,acronym,title,address,"
            "origin,priority,set_id,did_count,config_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (kind, spec, model, year, acronym, title, address, origin, priority,
             sid, n, ncfg))
        return cur.lastrowid


def did_items(w, rows):
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
                for sf in json.loads(subfields):
                    f = mdx_field(sf)
                    if f is not None:
                        if size and f["m"] >= size * 8:
                            continue
                        fields.append(f)
            except ValueError:
                pass
        lid = w.layout((name or "").strip() or f"DID {did:04X}", size, did_type, fields)
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
        items = did_items(w, c.execute(q_did, (fid,)))
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


def build_ucds_ipc(w, path):
    """C520 IPC DIDs extracted from UCDS process RAM. Only bit-positioned
    fields; lsb/msb already count from the LSB of the whole payload."""
    if not path or not Path(path).exists():
        print("   ucds ipc: skipped (file not found)")
        return
    d = json.load(open(path))
    items = []
    for did_hex, fl in d.items():
        did = to_int("0x" + did_hex)
        if did is None:
            continue
        size = None
        name = None
        fields = []
        for f in fl:
            size = size or to_int(f.get("byte_size"))
            if f.get("bit_start") is None or f.get("bit_end") is None:
                name = name or f.get("name")
                continue
            lo, hi = sorted((int(f["bit_start"]), int(f["bit_end"])))
            if size and hi >= size * 8:
                continue
            ff = {"n": f.get("name") or "?", "l": lo, "m": hi,
                  "t": "enum" if f.get("enum") else "uint"}
            if f.get("enum"):
                ff["e"] = [[int(v), str(t)] for v, t in f["enum"]]
            if f.get("unit") not in SKIP_UNITS:
                ff["u"] = f["unit"]
            fields.append(ff)
        if size is None and fields:
            size = (max(f["m"] for f in fields) + 8) // 8
        lid = w.layout(name or f"DID {did:04X}", size, "ucds", fields)
        wr = "03" if did_hex.upper().startswith("DE") else None
        items.append((did, lid, "", wr, "2" if wr else None))   # Ford level 2 = 27 03
    w.module("vehicle", None, "C520", None, "IPC", "IPC (C520, UCDS level-3 list)",
             0x720, "ucds", 1, items)
    print(f"   ucds ipc DIDs: {len(items)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--idsdb", default=str(DEFAULT_IDSDB))
    ap.add_argument("--ucds-ipc", default=str(DEFAULT_UCDS_IPC))
    ap.add_argument("-o", "--out", default=str(OUT))
    a = ap.parse_args()
    src = Path(a.idsdb).expanduser()
    out = Path(a.out)
    tmp = out.with_suffix(".tmp")
    w = Writer(tmp)
    t0 = time.time()
    print(f"building {out} from {src}")
    build_mdx(w, src / "mdx_data.sqlite")
    build_ccc(w, src / "ccf.sqlite")
    build_ucds_ipc(w, Path(a.ucds_ipc).expanduser())
    w.db.executemany("INSERT INTO meta VALUES(?,?)", [
        ("format", "1"),
        ("built", time.strftime("%Y-%m-%d %H:%M:%S")),
        ("source", "IDSdb mdx_data.sqlite + ccf.sqlite" +
         (" + UCDS IPC" if Path(a.ucds_ipc).exists() else "")),
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
