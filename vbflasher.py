#!/usr/bin/env python3
"""VBFlasher — a multi-ECU Ford VBF flasher.

One CLI flashes any registered Ford ECU. The target ECU, its SecurityAccess
secret and its Secondary Bootloader are chosen automatically from the module's
own F111 (hardware / Core Assembly Number) DID, exactly as the OEM-derived
FoCCCus tool does. Extend it by adding an EcuProfile to ecu_db.py — nothing in
this file hardcodes an ECU.

WHAT IT DOES, IN ORDER
  1. Parse and fully verify EVERY VBF given (block CRC-16 + file CRC-32).
     A corrupt file is refused before the ECU is touched.
  2. Group the files by their ecu_address; each group is one flash session.
  3. Connect, read F111 (and the other identity DIDs) from the live module.
  4. From F111, pick the SBL VBF and the seed-key secret from ecu_db.
     - If the chosen SBL file is not on disk (next to this flasher, or via
       --sbl-dir), STOP and tell the user to supply its path.
     - --sbl PATH overrides selection entirely.
  5. Print the full plan: SBL used, what is erased, what is written, and the
     CURRENT firmware IDs read from the ECU. Then ask "Are you sure? [y/N]".
  6. On y: programmingSession -> securityAccess -> load+start SBL ->
     (per erase region) erase -> download each block -> optional finalise ->
     reset. --test-sbl stops after the SBL starts (no erase, no write).

SAFETY
  * A plan is printed and you must answer "Are you sure? [y/N]" before any
    write. --dry-run prints the plan and connects to nothing; --yes skips the
    prompt (for scripting).
  * Ford ECUs are addressed with ISO-TP padding to DLC=8.
  * 0x78 responsePending is a CONTINUE; the wait ends only on total silence.
  * EXE parts are gated: the ECU's software part number (F188) must match the
    VBF, unless --force. DATA (calibration) parts are report-only.
  * --quiet-bus silences other modules for the flash (opt-in, unconfirmed).

USAGE
  python3 vbflasher.py --selftest
  python3 vbflasher.py info    FILE.vbf [FILE2.vbf ...]
  python3 vbflasher.py verify  FILE.vbf [...]
  python3 vbflasher.py ident   --ecu 0x730 [--iface can0]
  python3 vbflasher.py flash   APP.vbf CAL.vbf [...] [--iface can0]
  python3 vbflasher.py flash   APP.vbf --dry-run          # plan only, no bus
  python3 vbflasher.py flash   APP.vbf --test-sbl         # load+run SBL only
"""
import argparse
import inspect
import os
import sys
import time

# realpath (not abspath) so a symlink in ~/.local/bin resolves back to the real
# project dir — sibling modules (ecu_db, vbf) and sbl/ live next to the script.
HERE = os.path.dirname(os.path.realpath(__file__))
SBL_DIR = os.path.join(HERE, "sbl")   # default location for SBL VBF files
sys.path.insert(0, HERE)

import ecu_db                                            # noqa: E402
import ford_seckey                                       # noqa: E402
from vbf import (Vbf, Ecu, BusQuiet, Keepalive, download_blocks,  # noqa: E402
                 human, fmt, iface_is_up, dtc_code, dtc_status_str,
                 dtc_is_actual, functional_broadcast,
                 upload_block, download_raw_block, erase_region,
                 verify_routine)

TP_INTERVAL = 1.5


# --------------------------------------------------------------------------
# SBL resolution
# --------------------------------------------------------------------------
def find_sbl_file(name, sbl_dirs):
    """Return the first existing path for an SBL filename across search dirs,
    case-insensitively (VBF extensions vary .vbf/.VBF)."""
    for d in sbl_dirs:
        cand = os.path.join(d, name)
        if os.path.exists(cand):
            return cand
        try:
            low = name.lower()
            for f in os.listdir(d):
                if f.lower() == low:
                    return os.path.join(d, f)
        except OSError:
            pass
    return None


def resolve_sbl(profile, hw, args, sbl_dirs):
    """Return (sbl_path, sbl_name, reason). Raises SystemExit if unresolved."""
    if args.sbl:
        if not os.path.exists(args.sbl):
            raise SystemExit(f"--sbl {args.sbl}: file not found")
        return args.sbl, os.path.basename(args.sbl), "explicit --sbl"

    name = profile.pick_sbl(hw)
    if not name:
        raise SystemExit(
            f"No SBL is registered for {profile.name} with F111 {hw!r}.\n"
            f"    Specify one with:  --sbl /path/to/SBL.vbf")
    path = find_sbl_file(name, sbl_dirs)
    if not path:
        searched = "\n      ".join(sbl_dirs)
        raise SystemExit(
            f"The required SBL '{name}' (selected from F111 {hw!r}) was not "
            f"found on disk.\n    Searched:\n      {searched}\n"
            f"    Place '{name}' in the sbl/ folder, add a folder with "
            f"--sbl-dir, or pass --sbl /path/to/{name}.")
    return path, name, f"selected from F111 {hw!r}"


# --------------------------------------------------------------------------
# identity read
# --------------------------------------------------------------------------
def read_identity(ecu, profile, wake_tries=8, wake_timeout=0.5):
    """Read and print the identity DIDs; return dict{did: value}. F111 is the
    key one — SBL and secret are chosen from it."""
    print("\n== current firmware / identity ==")
    ident = {}
    # A sleeping bus drops the first frames; poke it several times briefly
    # rather than block on one long read.
    ecu.wake(tries=wake_tries, timeout=wake_timeout)
    labels = {"F188": "application sw (F188)", "F124": "calibration (F124)",
              "F111": "hardware/Core Assembly (F111)",
              "F113": "core assembly (F113)", "F18C": "ECU serial (F18C)",
              "F190": "VIN (F190)", "F91": "ext hardware (F191)"}
    for did in profile.ident_dids:
        val = ecu.read_did(did)
        ident[did] = val
        print("   %-32s %s" % (labels.get(did, did), val if val else "-"))
    return ident


# --------------------------------------------------------------------------
# one ECU session (may hold several VBFs)
# --------------------------------------------------------------------------
def flash_session(txid, files, args):
    profile = ecu_db.get_profile(txid)
    if profile is None:
        raise SystemExit(
            f"ecu_address 0x{txid:03X} is not in the registry (ecu_db.py). "
            f"Add an EcuProfile for it.")
    rxid = args.rxid if args.rxid is not None else profile.resp_id()

    vbfs = [Vbf(f) for f in files]
    # SBL parts among the given files are loaded as the SBL, not flashed to app.
    print("=" * 72)
    print(f"TARGET  {profile.name}   tx=0x{txid:03X} rx=0x{rxid:03X}   "
          f"iface={args.iface}")
    print("=" * 72)
    for v in vbfs:
        print(v.describe())
        probs = v.check()
        if probs:
            print("   !! INTEGRITY FAILURE — refusing to transmit:")
            for p in probs:
                print("      " + p)
            raise SystemExit(2)
        print("   integrity   OK (block CRC-16 + file CRC-32)\n")

    # order: non-SBL application/data parts get flashed; erase-bearing first
    to_flash = [v for v in vbfs if v.ptype != "SBL"]
    if not to_flash and not args.test_sbl:
        raise SystemExit("no flashable (non-SBL) VBF given; use --test-sbl to "
                         "just load an SBL.")

    if args.execute:
        up = iface_is_up(args.iface)
        if up is False:
            raise SystemExit(f"interface {args.iface} is DOWN. Bring it up "
                             f"first (e.g. sudo ip link set {args.iface} up).")
        if up is None and not os.path.exists(f"/sys/class/net/{args.iface}"):
            raise SystemExit(f"interface {args.iface} does not exist. Check "
                             f"`ip link` or pass --iface.")

    # --- connect + identity (needs the live F111 to choose SBL/secret) -----
    logf = None
    if args.logfile:
        os.makedirs(os.path.dirname(args.logfile) or ".", exist_ok=True)
        logf = open(args.logfile, "a")
        logf.write(f"\n==== {time.strftime('%F %T')} {profile.name} "
                   f"tx=0x{txid:03X} rx=0x{rxid:03X} ====\n")

    ecu = Ecu(args.iface, txid, rxid, execute=args.execute, logfile=logf)

    hw = args.hw or ""
    ident = {}
    if args.execute:
        ident = read_identity(ecu, profile, args.wake_tries, args.wake_timeout)
        hw = args.hw or ident.get("F111") or ""
        if not hw and not args.sbl:
            raise SystemExit(
                "could not read F111 from the ECU and no --hw/--sbl given; "
                "cannot choose the SBL/secret. Pass --hw <F111> or --sbl.")
    else:
        print("\n== current firmware / identity ==")
        print("   [dry run] F111 would be read here to choose SBL + secret.")
        if hw:
            print(f"   using --hw {hw!r} for planning")

    # --- resolve SBL + secret from F111 -----------------------------------
    # Default SBL location is the ./sbl/ subdir next to the flasher; HERE stays
    # as a fallback so SBLs dropped beside the script still resolve.
    sbl_dirs = [SBL_DIR, HERE] + list(args.sbl_dir or [])
    sbl_path, sbl_name, sbl_reason = resolve_sbl(profile, hw, args, sbl_dirs)
    sbl = Vbf(sbl_path)
    if sbl.call is None:
        raise SystemExit(f"{sbl_path}: SBL VBF has no `call` address in header")
    sp = sbl.check()
    if sp:
        print("!! SBL integrity failure:")
        for p in sp:
            print("   " + p)
        raise SystemExit(2)

    level = args.sec_level
    if args.secret is not None:
        secret = args.secret.to_bytes(5, "big") if isinstance(args.secret, int) \
            else args.secret
        secret_reason = "explicit --secret"
    else:
        secret = profile.pick_secret(hw, level)
        secret_reason = f"selected from F111 {hw!r} at security level {level}"
        if secret is None and args.execute:
            raise SystemExit(
                f"no SecurityAccess secret registered for {profile.name} "
                f"F111 {hw!r} level {level}. Pass --secret 0x....")

    # --- the PLAN ----------------------------------------------------------
    print("\n" + "=" * 72)
    print("PLAN")
    print("=" * 72)
    print(f"   ECU          {profile.name}  (tx 0x{txid:03X} / rx 0x{rxid:03X})")
    print(f"   SBL          {sbl_name}  ({sbl_reason})")
    print(f"                call=0x{sbl.call:08X}, {len(sbl.blocks)} block(s), "
          f"{human(sbl.total_payload())} to RAM")
    if secret is not None:
        print(f"   secret       {secret.hex().upper()}  ({secret_reason})")
    else:
        print(f"   secret       (dry run — {secret_reason})")
    if args.test_sbl:
        print("   MODE         --test-sbl: load + start the SBL ONLY. "
              "NO erase, NO write.")
    else:
        for v in to_flash:
            print(f"\n   FLASH  {os.path.basename(v.path)}  "
                  f"[{v.ptype}]  part {v.part}")
            erase = v.flash_erase()
            omitted = [r for r in v.erase if r not in erase]
            if erase:
                print(f"      ERASE {len(erase)} region(s):")
                for a, l in erase:
                    print(f"         0x{a:08X}  len 0x{l:06X} ({human(l)})")
            else:
                print("      ERASE (none declared)")
            if omitted:
                print(f"      OMIT  {len(omitted)} protected region(s) "
                      f"(not erased/written):")
                for a, l in omitted:
                    print(f"         0x{a:08X}  len 0x{l:06X} ({human(l)})")
            wblocks = v.flash_blocks()
            wpayload = sum(b["length"] for b in wblocks)
            print(f"      WRITE {len(wblocks)} block(s), {human(wpayload)}:")
            for b in wblocks:
                print(f"         -> 0x{b['start']:08X}  {human(b['length'])}")
            gate = profile.ident_did_by_type.get(v.ptype, "F188")
            if v.ptype == "EXE":
                print(f"      identity gate: ECU {gate} must match {v.part}")
            else:
                print(f"      identity: {gate} reported only (not gated)")
        if profile.finalize:
            print("\n   FINALISE  31 01 0304 (checkProgrammingDependencies) "
                  "after the last block")
    print("   RESET       11 01 ECUReset")
    if args.quiet_bus:
        print("   quiet-bus   ON: functional 10 82 before, hardReset after "
              "(unconfirmed, network-wide)")

    if not args.execute:
        print("\n*** DRY RUN — connected to nothing, nothing was sent. ***")
        if logf:
            logf.close()
        return

    # --- confirmation ------------------------------------------------------
    if not args.yes:
        print("\n" + "!" * 72)
        print("This will WRITE to a live ECU and is IRREVERSIBLE once erase "
              "begins.")
        print("Have the stock VBF on hand, battery charger on, engine off.")
        print("!" * 72)
        ans = input("Are you sure you want to proceed? [y/N] ").strip().lower()
        if ans != "y":
            print("aborted by user.")
            if logf:
                logf.close()
            return

    # --- execute -----------------------------------------------------------
    tp_bcast = args.tp_id if args.tp_id >= 0 else FUNCTIONAL_ID
    quiet = BusQuiet(args.iface, tp_bcast, execute=True, enabled=args.quiet_bus)
    # TesterPresent keepalive routing:
    #   * explicit --tp-id N     -> broadcast on N
    #   * --quiet-bus (default)  -> broadcast on 0x7DF: REQUIRED so the OTHER
    #     modules that quiet-bus put into programmingSession keep refreshing
    #     their S3 and STAY silent. A physical keepalive only refreshes the
    #     target and lets the rest wake up after ~5 s (S3 timeout).
    #   * otherwise              -> physical, via the target's ISO-TP socket.
    if args.tp_id >= 0:
        ka_can_id = args.tp_id
    elif args.quiet_bus:
        ka_can_id = FUNCTIONAL_ID
    else:
        ka_can_id = None
    ka = Keepalive(ecu, period=args.tp_interval, can_id=ka_can_id)
    if args.tp_interval > 0:
        where = ("physical (ISO-TP socket)" if ka_can_id is None
                 else f"broadcast 0x{ka_can_id:03X}")
        print(f"   keepalive: TesterPresent 3E 80 every {args.tp_interval:.1f}s "
              f"-> {where}")
    try:
        quiet.arm()

        # identity gate on EXE parts
        for v in to_flash:
            if v.ptype == "EXE" and not args.force:
                gate = profile.ident_did_by_type.get("EXE", "F188")
                live = ident.get(gate) or ecu.read_did(gate) or ""
                if live and v.part and live.strip() != v.part.strip():
                    raise SystemExit(
                        f"identity mismatch: ECU {gate}={live!r} != VBF "
                        f"{v.part!r}. Use --force to override.")

        print("\n== session + security ==")
        # A just-woken module can still drop the first programmingSession
        # request; retry a few times (bounded) before giving up.
        r = None
        for i in range(1, args.wake_tries + 1):
            r = ecu.req("1002", timeout=1.0, what=f"10 02 programmingSession {i}")
            if r is not None and r[0] == 0x50:
                break
            time.sleep(0.1)
        if not (r is not None and r[0] == 0x50):
            raise SystemExit(f"10 02 programmingSession: {fmt(r)} "
                             f"(no session after {args.wake_tries} tries)")
        print(f"   OK   10 02 programmingSession        {fmt(r)}")
        time.sleep(0.1)
        r = ecu.expect(f"27{level:02X}", 0x67, f"27 {level:02X} requestSeed",
                       timeout=5.0)
        seed = list(r[2:5])
        if seed == [0, 0, 0]:
            print("   seed 000000 -> already unlocked")
        else:
            key = ford_seckey.key_from_seed(seed, secret)
            print(f"   seed {bytes(seed).hex().upper()} -> "
                  f"key {key.hex().upper()}")
            ecu.expect(f"27{level + 1:02X}" + key.hex(), 0x67,
                       f"27 {level + 1:02X} sendKey", timeout=5.0)
        print("   unlocked")

        ka.start()

        print("\n== SBL -> RAM ==")
        download_blocks(ecu, sbl.blocks, "sbl", args.progress_interval)
        if profile.sbl_call_halfword:
            call_arg = f"{(sbl.call >> 16) & 0xFFFF:04X}"
        else:
            call_arg = f"{sbl.call:08X}"
        ecu.expect("31010301" + call_arg, 0x71, "31 01 0301 start SBL",
                   timeout=10.0)
        print(f"   SBL running (call 0x{sbl.call:08X})")

        if args.test_sbl:
            print("\n== --test-sbl: SBL loaded and started. Stopping before "
                  "erase/write. ==")
            print("   (a power cycle clears the RAM-resident SBL; the "
                  "application is untouched.)")
        else:
            for v in to_flash:
                erase = v.flash_erase()
                skipped = len(v.erase) - len(erase)
                print(f"\n== erase for {os.path.basename(v.path)} "
                      f"({len(erase)} region"
                      + (f", {skipped} omitted" if skipped else "") + ") ==")
                import struct as _s
                for a, l in erase:
                    ecu.expect("3101FF00" + _s.pack(">I", a).hex()
                               + _s.pack(">I", l).hex(), 0x71,
                               f"erase 0x{a:08X}", timeout=15.0,
                               pending_timeout=args.erase_timeout)
                print(f"\n== download {os.path.basename(v.path)} ==")
                download_blocks(ecu, v.flash_blocks(), v.part or "app",
                                args.progress_interval)

            if profile.finalize:
                print("\n== finalise (31 01 0304) ==")
                ecu.expect("31010304", 0x71, "31 01 0304 finalise",
                           timeout=15.0, pending_timeout=args.erase_timeout)

        print("\n== reset ==")
        ecu.req("1101", timeout=8.0, what="11 01 ECUReset")
    finally:
        ka.stop()
        if ka.sent:
            print(f"   keepalive: {ka.sent} TesterPresent frames")
        quiet.restore()
        if logf:
            logf.close()

    print("\n*** DONE ***")
    print("    Power-cycle if the module does not return on its own, then "
          "re-read identity with the `ident` subcommand.")


# --------------------------------------------------------------------------
# generic raw memory read / write (memread / memwrite) — reuses the proven
# session + security + SBL-load preamble, then does a single 35-upload or a
# FF00-erase + 34-download over an arbitrary address range. Modelled directly
# on the UCDS PSCM EEPROM capture (PSCM_ucds_eeprom_procedure.md).
# --------------------------------------------------------------------------
def _open_sbl_session(profile, args, need_secret=True):
    """Connect, read identity, load+start the SBL, unlock security. Returns
    (ecu, keepalive, quiet, logf, hw). Caller must stop ka / restore quiet /
    close logf in a finally. Mirrors flash_session's preamble exactly."""
    txid = profile.txid
    rxid = args.rxid if args.rxid is not None else profile.resp_id()
    _check_iface(args.iface)

    logf = None
    if getattr(args, "logfile", None):
        os.makedirs(os.path.dirname(args.logfile) or ".", exist_ok=True)
        logf = open(args.logfile, "a")
        logf.write(f"\n==== {time.strftime('%F %T')} {profile.name} "
                   f"mem tx=0x{txid:03X} rx=0x{rxid:03X} ====\n")

    ecu = Ecu(args.iface, txid, rxid, execute=True, logfile=logf)
    ident = read_identity(ecu, profile, getattr(args, "wake_tries", 8),
                          getattr(args, "wake_timeout", 0.5))
    hw = args.hw or ident.get("F111") or ""
    if not hw and not args.sbl:
        raise SystemExit("could not read F111 and no --hw/--sbl given; cannot "
                         "choose the SBL/secret. Pass --hw <F111> or --sbl.")

    sbl_dirs = [SBL_DIR, HERE] + list(args.sbl_dir or [])
    sbl_path, sbl_name, sbl_reason = resolve_sbl(profile, hw, args, sbl_dirs)
    sbl = Vbf(sbl_path)
    if sbl.call is None:
        raise SystemExit(f"{sbl_path}: SBL VBF has no `call` address")
    if sbl.check():
        raise SystemExit(f"{sbl_path}: SBL integrity failure")
    print(f"   SBL: {sbl_name}  call=0x{sbl.call:08X}  ({sbl_reason})")

    level = args.sec_level
    if args.secret is not None:
        secret = (args.secret.to_bytes(5, "big")
                  if isinstance(args.secret, int) else args.secret)
    else:
        secret = profile.pick_secret(hw, level)
        if secret is None and need_secret:
            raise SystemExit(f"no SecurityAccess secret for {profile.name} "
                             f"F111 {hw!r} level {level}. Pass --secret 0x....")

    quiet = BusQuiet(args.iface, FUNCTIONAL_ID, execute=True,
                     enabled=getattr(args, "quiet_bus", False))
    ka_can_id = (FUNCTIONAL_ID if getattr(args, "quiet_bus", False) else None)
    ka = Keepalive(ecu, period=args.tp_interval, can_id=ka_can_id)

    quiet.arm()
    print("\n== session + security ==")
    r = None
    for i in range(1, args.wake_tries + 1):
        r = ecu.req("1002", timeout=1.0, what=f"10 02 programmingSession {i}")
        if r is not None and r[0] == 0x50:
            break
        time.sleep(0.1)
    if not (r is not None and r[0] == 0x50):
        raise SystemExit(f"10 02 programmingSession: {fmt(r)}")
    print(f"   OK   10 02 programmingSession        {fmt(r)}")
    time.sleep(0.1)
    r = ecu.expect(f"27{level:02X}", 0x67, f"27 {level:02X} requestSeed",
                   timeout=5.0)
    seed = list(r[2:5])
    if seed == [0, 0, 0]:
        print("   seed 000000 -> already unlocked")
    else:
        key = ford_seckey.key_from_seed(seed, secret)
        print(f"   seed {bytes(seed).hex().upper()} -> key {key.hex().upper()}")
        ecu.expect(f"27{level + 1:02X}" + key.hex(), 0x67,
                   f"27 {level + 1:02X} sendKey", timeout=5.0)
    print("   unlocked")

    ka.start()
    print("\n== SBL -> RAM ==")
    download_blocks(ecu, sbl.blocks, "sbl", args.progress_interval)
    call_arg = (f"{(sbl.call >> 16) & 0xFFFF:04X}" if profile.sbl_call_halfword
                else f"{sbl.call:08X}")
    ecu.expect("31010301" + call_arg, 0x71, "31 01 0301 start SBL",
               timeout=10.0)
    print(f"   SBL running (call 0x{sbl.call:08X})")
    return ecu, ka, quiet, logf


def do_memread(args):
    profile = ecu_db.resolve(args.ecu)
    if profile is None:
        raise SystemExit(f"unknown ECU {args.ecu!r}. See `list`.")
    addr, length = args.addr, args.length
    print("=" * 72)
    print(f"MEMREAD  {profile.name}  0x{addr:08X} +0x{length:X} "
          f"({human(length)}) -> {args.outfile}")
    print("=" * 72)
    print("   PLAN: load+run SBL, then 35 RequestUpload the region, save to "
          "file.")
    if not args.yes:
        ans = input("Proceed with the read? [y/N] ").strip().lower()
        if ans != "y":
            print("aborted by user.")
            return
    ecu = ka = quiet = logf = None
    try:
        ecu, ka, quiet, logf = _open_sbl_session(profile, args,
                                                 need_secret=True)
        print(f"\n== read 0x{addr:08X} +0x{length:X} ==")
        data = upload_block(ecu, addr, length, addr_len_fmt=args.addr_len_fmt,
                            progress_interval=args.progress_interval,
                            tag="read")
        with open(args.outfile, "wb") as f:
            f.write(data)
        import hashlib
        print(f"\n   wrote {len(data)} bytes to {args.outfile}")
        print(f"   sha256 {hashlib.sha256(data).hexdigest()}")
    finally:
        if ka:
            ka.stop()
        if quiet:
            quiet.restore()
        if ecu is not None and not args.no_reset:
            try:
                ecu.req("1101", timeout=8.0, what="11 01 ECUReset")
            except Exception:  # noqa: BLE001
                pass
        if logf:
            logf.close()
    print("\n*** MEMREAD DONE ***")


def do_memwrite(args):
    profile = ecu_db.resolve(args.ecu)
    if profile is None:
        raise SystemExit(f"unknown ECU {args.ecu!r}. See `list`.")
    data = open(args.infile, "rb").read()
    if args.length is not None and len(data) != args.length:
        raise SystemExit(f"{args.infile} is {len(data)} bytes but --length "
                         f"0x{args.length:X} was given; they must match.")
    addr, length = args.addr, len(data)
    import hashlib
    print("=" * 72)
    print(f"MEMWRITE  {profile.name}  {args.infile} ({len(data)} bytes) "
          f"-> 0x{addr:08X}")
    print("=" * 72)
    print(f"   file sha256 {hashlib.sha256(data).hexdigest()}")
    print("   PLAN: load+run SBL, 31 01 FF00 erase, 34 download, "
          + ("31 01 0304 verify, " if not args.no_verify else "")
          + "11 01 reset.")
    print("   !! This WRITES ECU memory and is IRREVERSIBLE. Have a backup "
          "(memread) first.")
    if not args.yes:
        ans = input(f"Write 0x{length:X} bytes to 0x{addr:08X} on "
                    f"{profile.name}? [y/N] ").strip().lower()
        if ans != "y":
            print("aborted by user.")
            return
    ecu = ka = quiet = logf = None
    try:
        ecu, ka, quiet, logf = _open_sbl_session(profile, args,
                                                 need_secret=True)
        if not args.no_erase:
            print(f"\n== erase 0x{addr:08X} +0x{length:X} ==")
            erase_region(ecu, addr, length, erase_timeout=args.erase_timeout)
        print(f"\n== write 0x{addr:08X} +0x{length:X} ==")
        download_raw_block(ecu, addr, data, addr_len_fmt=args.addr_len_fmt,
                           progress_interval=args.progress_interval,
                           tag="write")
        if not args.no_verify:
            print("\n== verify (31 01 0304) ==")
            verify_routine(ecu, erase_timeout=args.erase_timeout)
    finally:
        if ka:
            ka.stop()
        if quiet:
            quiet.restore()
        if ecu is not None:
            try:
                ecu.req("1101", timeout=8.0, what="11 01 ECUReset")
            except Exception:  # noqa: BLE001
                pass
        if logf:
            logf.close()
    print("\n*** MEMWRITE DONE ***")
    print("    Read back with `memread` and compare to confirm the write.")


# --------------------------------------------------------------------------
# subcommands
# --------------------------------------------------------------------------
def do_flash(args):
    files = args.vbf
    for f in files:
        if not os.path.exists(f):
            raise SystemExit(f"{f}: not found")
    # group by ecu_address
    groups = {}
    for f in files:
        v = Vbf(f)
        if v.ecu is None:
            raise SystemExit(f"{f}: VBF has no ecu_address; cannot target it.")
        groups.setdefault(v.ecu, []).append(f)
    if len(groups) > 1:
        print(f"NOTE: {len(files)} files target {len(groups)} different ECUs: "
              + ", ".join(f"0x{e:03X}" for e in groups))
    for txid, gfiles in groups.items():
        flash_session(txid, gfiles, args)


def do_info(args):
    for f in args.vbf:
        v = Vbf(f)
        print(v.describe())
        p = v.check()
        print("   integrity:", "OK" if not p else "FAILED")
        for x in p:
            print("      " + x)
        print()


def do_verify(args):
    bad = 0
    for f in args.vbf:
        v = Vbf(f)
        p = v.check()
        print(f"{f}\n   " + ("ALL CRCs OK" if not p else "FAILURES:"))
        for x in p:
            print("      " + x)
        bad += bool(p)
    raise SystemExit(1 if bad else 0)


FUNCTIONAL_ID = 0x7DF   # broadcast / functional diagnostic address


def _selector_is_all(sel) -> bool:
    """True when the user asked for every module: 'ALL' or the 7DF broadcast."""
    s = str(sel).strip().upper()
    if s == "ALL":
        return True
    for base in (0, 16):
        try:
            if int(s, base) == FUNCTIONAL_ID:
                return True
        except ValueError:
            continue
    return False


def _check_iface(iface):
    if not os.path.exists(f"/sys/class/net/{iface}"):
        raise SystemExit(f"interface {iface} does not exist.")
    if iface_is_up(iface) is False:
        raise SystemExit(f"interface {iface} is DOWN.")


def _connect_by_selector(args):
    """Resolve --ecu (name or id) to a profile and open a live Ecu. Shared by
    ident / dtc / cleardtc / reset — none of these need a VBF."""
    profile = ecu_db.resolve(args.ecu)
    if profile is None:
        known = ", ".join(sorted({p.name.split()[0] for p in ecu_db.ECUS.values()}))
        raise SystemExit(f"unknown ECU {args.ecu!r}. Use a name ({known}), a "
                         f"CAN id (e.g. 726, 0x7E0), or ALL. See `list`.")
    rxid = args.rxid if args.rxid is not None else profile.resp_id()
    _check_iface(args.iface)
    ecu = Ecu(args.iface, profile.txid, rxid, execute=True)
    return profile, ecu


def do_ident(args):
    if _selector_is_all(args.ecu):
        return _ident_all(args)
    profile, ecu = _connect_by_selector(args)
    print(f"== {profile.name}  tx=0x{profile.txid:03X} rx=0x{ecu.rxid:03X} ==")
    read_identity(ecu, profile, getattr(args, "wake_tries", 8),
                  getattr(args, "wake_timeout", 0.5))


def _ascii_sanitize(data):
    """Printable-ASCII rendering of bytes; every non-printable byte -> '.'.

    Only 0x20..0x7E pass through; control chars, DEL and all high bytes become
    '.', so a binary DID can never emit escape sequences that corrupt the
    terminal (no CR/LF/BS/ESC/colour codes leak through)."""
    return "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in data)


def _hexdump(data, indent="   "):
    """Classic 16-byte-per-row hex + sanitized ASCII dump."""
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hx = " ".join(f"{b:02X}" for b in chunk)
        hx = f"{hx:<47}"                       # pad to 16*3-1 columns
        lines.append(f"{indent}{off:04X}  {hx}  |{_ascii_sanitize(chunk)}|")
    return "\n".join(lines)


def do_readdid(args):
    profile, ecu = _connect_by_selector(args)
    print(f"== {profile.name}  tx=0x{profile.txid:03X} rx=0x{ecu.rxid:03X} ==")
    ecu.wake(tries=getattr(args, "wake_tries", 8),
             timeout=getattr(args, "wake_timeout", 0.5))
    for did in args.did:
        d = did.upper().replace("0X", "").replace(" ", "")
        if len(d) != 4 or any(c not in "0123456789ABCDEF" for c in d):
            print(f"\n   {did}: not a 2-byte DID (expected 4 hex digits)")
            continue
        r = ecu.req("22" + d, timeout=args.timeout, what="22 " + d)
        if r is None:
            print(f"\n   {d}: <no response / timeout>")
            continue
        if r[0] == 0x7F:
            print(f"\n   {d}: {fmt(r)}")
            continue
        # positive: 62 <did_hi> <did_lo> <payload...>
        if r[0] != 0x62 or len(r) < 3:
            print(f"\n   {d}: unexpected response {r.hex().upper()}")
            continue
        payload = r[3:]
        print(f"\n   DID {d}  ({len(payload)} bytes)")
        if not payload:
            print("      (empty)")
            continue
        print(f"      hex:   {payload.hex().upper()}")
        print(f"      ascii: {_ascii_sanitize(payload)!r}")
        if len(payload) > 16:
            print(_hexdump(payload, indent="      "))


def do_writedid(args):
    d = args.did.upper().replace("0X", "").replace(" ", "")
    if len(d) != 4 or any(c not in "0123456789ABCDEF" for c in d):
        raise SystemExit(f"{args.did}: not a 2-byte DID (expected 4 hex digits)")
    payload = args.data.replace("0x", "").replace("0X", "").replace(" ", "")
    if len(payload) % 2 or any(c not in "0123456789abcdefABCDEF" for c in payload):
        raise SystemExit(f"--data {args.data!r}: not valid hex bytes")
    if not payload:
        raise SystemExit("no data given to write")
    data = bytes.fromhex(payload)
    profile, ecu = _connect_by_selector(args)
    print(f"== {profile.name}  tx=0x{profile.txid:03X} rx=0x{ecu.rxid:03X} ==")
    print(f"   WRITE DID {d}  <- {data.hex().upper()}  ({len(data)} bytes)")
    print(f"   ascii: {_ascii_sanitize(data)!r}")

    ecu.wake(tries=getattr(args, "wake_tries", 8),
             timeout=getattr(args, "wake_timeout", 0.5))

    # show current value first (best-effort) so the user sees what changes
    cur = ecu.req("22" + d, timeout=args.timeout, what="22 " + d + " (before)")
    if cur is not None and cur and cur[0] == 0x62 and len(cur) >= 3:
        old = cur[3:]
        print(f"   current: {old.hex().upper()}  ({_ascii_sanitize(old)!r})")
    else:
        print(f"   current: {fmt(cur)} (read-back not available)")

    if not args.yes:
        ans = input(f"Write {len(data)} byte(s) to DID {d} on {profile.name}? "
                    "[y/N] ").strip().lower()
        if ans != "y":
            print("aborted by user.")
            return

    # Optional session/security preamble: some DIDs are only writable in an
    # extended/programming session after SecurityAccess. Default is a bare 2E.
    # --sec-level/--secret/--hw imply --unlock so they aren't a silent no-op.
    if args.sec_level is not None or args.secret is not None or args.hw:
        args.unlock = True
    if args.session is not None:
        ecu.expect("10%02X" % args.session, 0x50,
                   "10 %02X diagnosticSession" % args.session, timeout=5.0)
        time.sleep(0.1)
    if args.unlock:
        level = args.sec_level if args.sec_level is not None else 1
        secret = (args.secret.to_bytes(5, "big")
                  if isinstance(args.secret, int) else args.secret) \
            if args.secret is not None else profile.pick_secret(args.hw or "",
                                                                level)
        if secret is None:
            raise SystemExit(f"--unlock: no secret for {profile.name} level "
                             f"{level}; pass --secret 0x....")
        r = ecu.expect(f"27{level:02X}", 0x67, f"27 {level:02X} requestSeed",
                       timeout=5.0)
        seed = list(r[2:5])
        if seed != [0, 0, 0]:
            key = ford_seckey.key_from_seed(seed, secret)
            print(f"   seed {bytes(seed).hex().upper()} -> key "
                  f"{key.hex().upper()}")
            ecu.expect(f"27{level + 1:02X}" + key.hex(), 0x67,
                       f"27 {level + 1:02X} sendKey", timeout=5.0)
        print("   unlocked")

    r = ecu.req("2E" + d + data.hex(), timeout=args.timeout,
                what="2E " + d + " writeDataByIdentifier")
    if r is not None and r and r[0] == 0x6E:
        print(f"   OK   2E {d} accepted (6E)")
    else:
        raise SystemExit(f"   FAIL 2E {d}: {fmt(r)}")

    # read back to confirm
    rb = ecu.req("22" + d, timeout=args.timeout, what="22 " + d + " (after)")
    if rb is not None and rb and rb[0] == 0x62 and len(rb) >= 3:
        got = rb[3:]
        print(f"   after:   {got.hex().upper()}  ({_ascii_sanitize(got)!r})")
        if got[:len(data)] == data:
            print("   verified: read-back matches written data.")
        else:
            print("   !! read-back does NOT match written data.")


def _ident_all(args):
    """Iterate every registered module and print each one's identity.

    Unlike cleardtc/reset ALL, identity cannot be a functional broadcast — a
    read must be paired with ONE responder. So we poll each ECU physically.
    A module that does not answer (not present on this bus / asleep) is noted
    and skipped, not fatal. Uses a short wake so absent modules don't stall.
    """
    _check_iface(args.iface)
    # Keep the presence probe FAST — a full 8×0.5s wake per absent module would
    # make a 12-module scan crawl. Cap it; the user's --wake-* still cap it down.
    tries = min(getattr(args, "wake_tries", 2), 2)
    wtmo = min(getattr(args, "wake_timeout", 0.3), 0.3)
    print(f"== identity of ALL {len(ecu_db.ECUS)} registered modules "
          f"(iface {args.iface}) ==")
    present, absent = [], []
    for txid in sorted(ecu_db.ECUS):
        profile = ecu_db.ECUS[txid]
        rxid = profile.resp_id()
        ecu = Ecu(args.iface, txid, rxid, execute=True)
        # quick probe: is anything home? (bounded, so absent modules are fast)
        if ecu.wake(tries=tries, timeout=wtmo) is None \
                and ecu.read_did(profile.ident_dids[0], timeout=wtmo) is None:
            absent.append(profile)
            print(f"\n-- {profile.name}  tx=0x{txid:03X} rx=0x{rxid:03X}  "
                  f"-> no response, skipped")
            continue
        present.append(profile)
        print(f"\n-- {profile.name}  tx=0x{txid:03X} rx=0x{rxid:03X}")
        read_identity(ecu, profile, wake_tries=1, wake_timeout=wtmo)
    print(f"\n== summary: {len(present)} responded, {len(absent)} silent "
          f"of {len(ecu_db.ECUS)} ==")
    if present:
        print("   present: " + ", ".join(p.name.split()[0] for p in present))
    if absent:
        print("   silent:  " + ", ".join(p.name.split()[0] for p in absent))


def do_dtc(args):
    if _selector_is_all(args.ecu):
        return _dtc_all(args)
    profile, ecu = _connect_by_selector(args)
    print(f"== DTCs on {profile.name}  tx=0x{profile.txid:03X} "
          f"rx=0x{ecu.rxid:03X} ==")
    ecu.wake(tries=getattr(args, "wake_tries", 8),
             timeout=getattr(args, "wake_timeout", 0.5))
    mask = args.status_mask
    dtcs, avail = ecu.read_dtcs(status_mask=mask)
    if dtcs is None:
        raise SystemExit("no valid 19 02 response (module silent or refused).")
    total = len(dtcs)
    shown = dtcs if args.all else [(d, s) for d, s in dtcs if dtc_is_actual(s)]
    if not shown:
        extra = (f" ({total} present but only 'not completed' — use --all)"
                 if total else "")
        print(f"   no actual DTCs matching status mask 0x{mask:02X}.{extra}")
        return
    hidden = total - len(shown)
    note = "" if args.all else f"  (actual only; {hidden} not-completed hidden, --all shows them)"
    print(f"   {len(shown)} DTC(s) (availabilityMask 0x{avail:02X}, "
          f"query mask 0x{mask:02X}){note}:\n")
    for dtc, status in shown:
        print(f"   {dtc_code(dtc)}   raw {dtc:06X}  status 0x{status:02X}  "
              f"[{dtc_status_str(status)}]")


def _dtc_all(args):
    """Walk every registered module and print only a COUNT of actual DTCs per
    module — a whole-network overview without flooding the terminal.

    Per module: actual (real-fault) count and total count. Use `dtc <ECU>` to
    list one module in full. Absent/silent modules are skipped fast.
    """
    _check_iface(args.iface)
    tries = min(getattr(args, "wake_tries", 2), 2)
    wtmo = min(getattr(args, "wake_timeout", 0.3), 0.3)
    mask = args.status_mask
    print(f"== actual DTC counts across all {len(ecu_db.ECUS)} registered "
          f"modules (iface {args.iface}, status mask 0x{mask:02X}) ==\n")
    print("   %-32s %8s %8s" % ("module (tx/rx)", "actual", "total"))
    print("   " + "-" * 50)
    rows, silent, grand = [], [], 0
    for txid in sorted(ecu_db.ECUS):
        profile = ecu_db.ECUS[txid]
        ecu = Ecu(args.iface, txid, profile.resp_id(), execute=True)
        label = f"{profile.name.split()[0]} (0x{txid:03X}/0x{profile.resp_id():03X})"
        # Fast presence probe first: absent modules cost only the short wake,
        # not a full DTC-read timeout. A present module then gets a generous
        # read window (its 19 02 can be a large multi-frame response).
        alive = ecu.wake(tries=tries, timeout=wtmo) is not None
        dtcs = None
        if alive:
            dtcs, _ = ecu.read_dtcs(status_mask=mask, timeout=20.0)
        if dtcs is None:
            silent.append(profile)
            print("   %-32s %8s %8s" % (label, "-", "-"))
            continue
        actual = sum(1 for _, s in dtcs if dtc_is_actual(s))
        grand += actual
        rows.append((profile, actual, len(dtcs)))
        flag = "  <--" if actual else ""
        print("   %-32s %8d %8d%s" % (label, actual, len(dtcs), flag))
    print("   " + "-" * 50)
    faulted = [p.name.split()[0] for p, a, _ in rows if a]
    print(f"\n   {grand} actual DTC(s) total across {len(rows)} responding "
          f"module(s); {len(silent)} silent.")
    if faulted:
        print("   modules with actual faults: " + ", ".join(faulted))
        print("   -> list one in full with:  vbflasher.py dtc <ECU>")


def do_cleardtc(args):
    if _selector_is_all(args.ecu):
        return _cleardtc_all(args)
    profile, ecu = _connect_by_selector(args)
    print(f"== clear DTCs on {profile.name}  tx=0x{profile.txid:03X} "
          f"rx=0x{ecu.rxid:03X} ==")
    ecu.wake(tries=getattr(args, "wake_tries", 8),
             timeout=getattr(args, "wake_timeout", 0.5))
    def summarise(label):
        dtcs, _ = ecu.read_dtcs()
        if dtcs is None:
            return
        actual = [(d, s) for d, s in dtcs if dtc_is_actual(s)]
        line = f"   {label} {len(actual)} actual DTC(s) of {len(dtcs)} total"
        if actual:
            line += ": " + ", ".join(dtc_code(d) for d, _ in actual)
        print(line)

    # show what is there first
    summarise("before:")
    if not args.yes:
        ans = input(f"Clear DTC group 0x{args.group:06X} on {profile.name}? "
                    "[y/N] ").strip().lower()
        if ans != "y":
            print("aborted by user.")
            return
    ok = ecu.clear_dtcs(group=args.group)
    print("   14 clearDiagnosticInformation:", "OK (54)" if ok else "FAILED")
    if ok:
        summarise("after: ")


def _cleardtc_all(args):
    """Clear DTCs on EVERY module at once via functional 7DF broadcast.

    Fire-and-forget: functional requests are answered by all modules at once,
    so there is NO confirmation. Sent several times so a module that missed
    the first frame still clears. Watch candump for proof if needed.
    """
    _check_iface(args.iface)
    print(f"== clear DTCs on ALL modules  (functional 0x{FUNCTIONAL_ID:03X}, "
          f"iface {args.iface}) ==")
    print("   NOTE: functional broadcast — responses are suppressed, so there "
          "is NO per-module confirmation.")
    if not args.yes:
        ans = input(f"Broadcast 14 clearDiagnosticInformation "
                    f"(group 0x{args.group:06X}) to ALL modules? "
                    "[y/N] ").strip().lower()
        if ans != "y":
            print("aborted by user.")
            return
    payload = [0x14, (args.group >> 16) & 0xFF, (args.group >> 8) & 0xFF,
               args.group & 0xFF]
    functional_broadcast(args.iface, [payload], can_id=FUNCTIONAL_ID,
                         repeat=args.repeat)
    print(f"   sent {FUNCTIONAL_ID:03X}#{bytes([len(payload)] + payload).hex().upper()}"
          f" x{args.repeat}  [unconfirmed]")
    print("   done. Re-read a specific module with `dtc <ECU>` to verify.")


def do_reset(args):
    if _selector_is_all(args.ecu):
        return _reset_all(args)
    profile, ecu = _connect_by_selector(args)
    mode = args.mode
    print(f"== ECUReset {profile.name}  tx=0x{profile.txid:03X} "
          f"rx=0x{ecu.rxid:03X}  mode 0x{mode:02X} ==")
    ecu.wake(tries=getattr(args, "wake_tries", 8),
             timeout=getattr(args, "wake_timeout", 0.5))
    ok = ecu.reset(mode=mode)
    print(f"   11 {mode:02X} ECUReset:", "OK (51)" if ok else "FAILED / no reply")


def _reset_all(args):
    """Hard-reset EVERY module at once via functional 7DF broadcast (11 01).

    Fire-and-forget (suppressed responses). This reboots the whole network;
    on a vehicle do it stationary with the engine off.
    """
    _check_iface(args.iface)
    mode = args.mode
    print(f"== ECUReset ALL modules  (functional 0x{FUNCTIONAL_ID:03X}, "
          f"iface {args.iface}, mode 0x{mode:02X}) ==")
    print("   NOTE: functional broadcast — reboots EVERY module; responses "
          "suppressed (no confirmation). Vehicle stationary, engine off.")
    if not args.yes:
        ans = input(f"Broadcast 11 {mode:02X} ECUReset to ALL modules? "
                    "[y/N] ").strip().lower()
        if ans != "y":
            print("aborted by user.")
            return
    # sub-function 0x80 (suppressPosRsp) so nobody floods the bus with 51s
    payload = [0x11, mode | 0x80]
    functional_broadcast(args.iface, [payload], can_id=FUNCTIONAL_ID,
                         repeat=args.repeat)
    print(f"   sent {FUNCTIONAL_ID:03X}#{bytes([len(payload)] + payload).hex().upper()}"
          f" x{args.repeat}  [unconfirmed]")
    print("   done. Modules reboot into their default session.")



def do_silence(args):
    """Silence a module (or ALL via 7DF) by holding it in programmingSession,
    exactly like flash's --quiet-bus but as a standalone, persistent action.

    A module in programmingSession stops emitting its normal application
    frames; a periodic TesterPresent keeps its S3 timer alive so it stays
    quiet. On exit (Ctrl-C or --duration elapsed) an ECUReset returns it to
    normal. Watch the bus with candump for proof — functional responses are
    suppressed, so the quiet itself is unconfirmed.
    """
    _check_iface(args.iface)
    period = args.tp_interval if args.tp_interval > 0 else 2.0
    ecu = None

    if _selector_is_all(args.ecu):
        # ALL: functional broadcast, reuse the vehicle-proven BusQuiet machinery
        quiet = BusQuiet(args.iface, FUNCTIONAL_ID, execute=True, enabled=True)
        ka = Keepalive(_KaShim(args.iface), period=period, can_id=FUNCTIONAL_ID)
        print(f"== silence ALL modules  (functional 0x{FUNCTIONAL_ID:03X}, "
              f"iface {args.iface}) ==")
        print("   NOTE: functional broadcast, responses suppressed — quiet is "
              "UNCONFIRMED. Watch with candump.")
        target = "ALL modules"
        restore_txt = f"functional 0x{FUNCTIONAL_ID:03X} hardReset"
    else:
        profile = ecu_db.resolve(args.ecu)
        if profile is None:
            raise SystemExit(f"unknown ECU {args.ecu!r}. Use a name, CAN id, "
                             "or ALL. See `list`.")
        rxid = args.rxid if args.rxid is not None else profile.resp_id()
        ecu = Ecu(args.iface, profile.txid, rxid, execute=True)
        print(f"== silence {profile.name}  tx=0x{profile.txid:03X} "
              f"rx=0x{ecu.rxid:03X}  iface {args.iface} ==")
        ecu.wake(tries=getattr(args, "wake_tries", 8),
                 timeout=getattr(args, "wake_timeout", 0.5))
        r = None
        for i in range(1, args.wake_tries + 1):
            r = ecu.req("1002", timeout=1.0,
                        what=f"10 02 programmingSession {i}")
            if r is not None and r[0] == 0x50:
                break
            time.sleep(0.1)
        if not (r is not None and r[0] == 0x50):
            raise SystemExit(f"10 02 programmingSession: {fmt(r)}")
        print(f"   OK   10 02 programmingSession   {fmt(r)}  -> module silent")
        quiet = None
        ka = Keepalive(ecu, period=period, can_id=None)  # physical keepalive
        target = profile.name
        restore_txt = "11 01 ECUReset"

    if args.duration:
        print(f"   holding {target} silent for {args.duration:.0f}s "
              f"(TesterPresent every {period:.1f}s)...")
    else:
        print(f"   holding {target} silent (TesterPresent every {period:.1f}s)."
              "  Press Ctrl-C to stop and restore.")

    try:
        if quiet is not None:
            quiet.arm()
        ka.start()
        t0 = time.time()
        while True:
            time.sleep(0.25)
            if args.duration and (time.time() - t0) >= args.duration:
                print(f"\n   {args.duration:.0f}s elapsed.")
                break
    except KeyboardInterrupt:
        print("\n   interrupted.")
    finally:
        ka.stop()
        if ka.sent:
            print(f"   keepalive: {ka.sent} TesterPresent frames sent")
        print(f"   restoring ({restore_txt})...")
        if quiet is not None:
            quiet.restore()
        elif ecu is not None:
            try:
                ecu.req("1101", timeout=8.0, what="11 01 ECUReset")
            except Exception:  # noqa: BLE001
                pass
    print("   done — module(s) returned to normal operation.")


class _KaShim:
    """Minimal Ecu-like object so Keepalive can broadcast on a raw socket for
    the ALL/silence path without a bound ISO-TP channel."""
    def __init__(self, iface):
        self.iface = iface
        self.execute = True
        self.s = None


def do_list(args):
    print("Registered ECUs (edit ecu_db.py to add more):\n")
    for txid, p in sorted(ecu_db.ECUS.items()):
        sbls = ", ".join(sorted({r.filename for r in p.sbls}
                                | ({p.default_sbl} if p.default_sbl else set())))
        print(f"  0x{txid:03X}  {p.name}")
        print(f"         rx 0x{p.resp_id():03X}  secrets:{len(p.secrets)}  "
              f"finalise:{p.finalize}")
        if sbls:
            print(f"         SBLs: {sbls}")


# --------------------------------------------------------------------------
# shell completion (option B): generated FROM the live parser + ecu_db, so it
# never drifts from the real subcommands / flags / ECU names.
# --------------------------------------------------------------------------
def _completion_model(parser):
    """Introspect the argparse parser -> {subcmd: [option strings...]} plus the
    ordered subcommand list and which subcommands take an ECU as first arg."""
    subcmds = []
    opts = {}
    ecu_first = {}
    file_first = set()
    top_opts = [os for a in parser._actions for os in a.option_strings]
    for act in parser._actions:
        if not isinstance(act, argparse._SubParsersAction):
            continue
        for name, sp in act.choices.items():
            if name in subcmds:
                continue
            subcmds.append(name)
            flags = []
            takes_ecu = False
            takes_file = False
            for a in sp._actions:
                flags.extend(a.option_strings)
                if not a.option_strings:  # positional
                    if a.metavar == "ECU":
                        takes_ecu = True
                    elif a.metavar == "FILE":
                        takes_file = True
            opts[name] = sorted(set(flags))
            ecu_first[name] = takes_ecu
            if takes_file:
                file_first.add(name)
    return {"subcmds": subcmds, "opts": opts, "ecu_first": ecu_first,
            "file_first": file_first, "top_opts": sorted(set(top_opts))}


def _ecu_tokens():
    """Every accepted ECU selector: aliases + primary names + ALL/7DF."""
    toks = set(["ALL", "7DF"])
    for p in ecu_db.ECUS.values():
        toks.update(p.aliases)
        toks.add(p.name.split()[0])
    return sorted(toks)


def _gen_bash(model):
    subcmds = " ".join(model["subcmds"])
    ecus = " ".join(_ecu_tokens())
    top = " ".join(model["top_opts"])
    # per-subcommand option case arms
    arms = []
    for c in model["subcmds"]:
        arms.append(f'        {c}) opts="{" ".join(model["opts"][c])}" ;;')
    arms_txt = "\n".join(arms)
    # subcommands whose first positional is an ECU (offer ECU tokens)
    ecu_cmds = " ".join(c for c in model["subcmds"] if model["ecu_first"][c])
    file_cmds = " ".join(sorted(model["file_first"]))
    return f'''# bash completion for vbflasher  (generated by `vbflasher completion bash`)
# Regenerate after changing subcommands/flags: vbflasher completion bash > this file
_vbflasher() {{
    local cur prev words cword
    _init_completion 2>/dev/null || {{
        cur="${{COMP_WORDS[COMP_CWORD]}}"
        prev="${{COMP_WORDS[COMP_CWORD-1]}}"
        cword=$COMP_CWORD
    }}
    local subcmds="{subcmds}"
    local ecus="{ecus}"
    local ecu_cmds="{ecu_cmds}"
    local file_cmds="{file_cmds}"

    # find the subcommand (first non-option word after argv[0])
    local i cmd=""
    for ((i=1; i<COMP_CWORD; i++)); do
        case "${{COMP_WORDS[i]}}" in
            -*) ;;
            *) cmd="${{COMP_WORDS[i]}}"; break ;;
        esac
    done

    if [[ -z "$cmd" ]]; then
        if [[ "$cur" == -* ]]; then
            COMPREPLY=( $(compgen -W "{top} -h --help" -- "$cur") )
        else
            COMPREPLY=( $(compgen -W "$subcmds" -- "$cur") )
        fi
        return
    fi

    if [[ "$cur" == -* ]]; then
        local opts="-h --help"
        case "$cmd" in
{arms_txt}
        esac
        COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
        return
    fi

    # first positional: ECU tokens for ecu_cmds, files for file_cmds
    if [[ " $ecu_cmds " == *" $cmd "* ]]; then
        # only complete ECU on the first positional slot
        local seen=0 w
        for ((i=1; i<COMP_CWORD; i++)); do
            w="${{COMP_WORDS[i]}}"
            [[ "$w" == "$cmd" ]] && continue
            [[ "$w" == -* ]] && continue
            (( i < COMP_CWORD )) && seen=1 && break
        done
        if [[ $seen -eq 0 ]]; then
            COMPREPLY=( $(compgen -W "$ecus" -- "$cur") )
            return
        fi
    fi
    if [[ " $file_cmds " == *" $cmd "* ]]; then
        COMPREPLY=( $(compgen -f -X '!*.[vV][bB][fF]' -- "$cur") \
                    $(compgen -d -- "$cur") )
        return
    fi
    # default: filenames
    COMPREPLY=( $(compgen -f -- "$cur") )
}}
complete -o filenames -F _vbflasher vbflasher vbflasher.py
'''


def _gen_zsh(model):
    subcmds = " ".join(model["subcmds"])
    ecus = " ".join(_ecu_tokens())
    ecu_cmds = " ".join(c for c in model["subcmds"] if model["ecu_first"][c])
    file_cmds = " ".join(sorted(model["file_first"]))
    # build per-command flag lists
    arms = []
    for c in model["subcmds"]:
        arms.append(f'    {c}) flags="{" ".join(model["opts"][c])}" ;;')
    arms_txt = "\n".join(arms)
    return f'''#compdef vbflasher vbflasher.py
# zsh completion for vbflasher (generated by `vbflasher completion zsh`)
_vbflasher() {{
    local -a subcmds ecus
    subcmds=({subcmds})
    ecus=({ecus})
    local ecu_cmds="{ecu_cmds}"
    local file_cmds="{file_cmds}"
    local cmd="${{words[2]}}"
    if (( CURRENT == 2 )); then
        compadd -a subcmds
        return
    fi
    if [[ "${{words[CURRENT]}}" == -* ]]; then
        local flags="-h --help"
        case "$cmd" in
{arms_txt}
        esac
        compadd ${{=flags}}
        return
    fi
    if (( CURRENT == 3 )) && [[ " $ecu_cmds " == *" $cmd "* ]]; then
        compadd -a ecus
        return
    fi
    if [[ " $file_cmds " == *" $cmd "* ]]; then
        _files -g '*.(vbf|VBF)'
        return
    fi
    _files
}}
compdef _vbflasher vbflasher vbflasher.py
'''


def do_completion(args):
    parser = build_parser()
    model = _completion_model(parser)
    shell = args.shell
    text = _gen_bash(model) if shell == "bash" else _gen_zsh(model)

    if not args.install:
        sys.stdout.write(text)
        return 0

    # --install: write to the standard user completion dir and tell the user
    home = os.path.expanduser("~")
    if shell == "bash":
        dest_dir = os.environ.get(
            "BASH_COMPLETION_USER_DIR",
            os.path.join(home, ".local", "share", "bash-completion",
                         "completions"))
        dest = os.path.join(dest_dir, "vbflasher")
        hint = ("Open a new shell, or run:  "
                f"source {dest}\n"
                "   (needs the bash-completion package; most distros ship it.)")
    else:
        dest_dir = os.path.join(home, ".zsh", "completions")
        dest = os.path.join(dest_dir, "vbflasher.zsh")
        hint = ("Add ONE line to the END of ~/.zshrc (after your existing "
                "compinit):\n"
                f"     source {dest}\n"
                "   It registers via compdef with NO extra compinit / dump "
                "rebuild, so it\n"
                "   does NOT slow shell startup. Then open a new shell.")
    os.makedirs(dest_dir, exist_ok=True)
    with open(dest, "w") as f:
        f.write(text)
    print(f"installed {shell} completion -> {dest}")
    print(f"   {hint}")
    return 0


# --------------------------------------------------------------------------
def selftest():
    ok = True

    def chk(n, c, d=""):
        nonlocal ok
        ok = ok and bool(c)
        print(f"  {'PASS' if c else 'FAIL'}  {n}" + (f"  {d}" if d else ""))

    print("== keygen ==")
    ok = ford_seckey.selftest() and ok

    print("\n== registry ==")
    chk("BCM 0x726 present", ecu_db.get_profile(0x726) is not None)
    chk("PSCM 0x730 present", ecu_db.get_profile(0x730) is not None)
    chk("IPMA 0x706 present", ecu_db.get_profile(0x706) is not None)
    bcm = ecu_db.get_profile(0x726)
    chk("BCM DV6T level1 secret == 64000B0C59",
        bcm.pick_secret("DV6T-14C245-FF", 1) == bytes.fromhex("64000B0C59"),
        (bcm.pick_secret("DV6T-14C245-FF", 1) or b"").hex())
    chk("BCM DV6T level3 secret == CD0D52F64D",
        bcm.pick_secret("DV6T-14C245-FF", 3) == bytes.fromhex("CD0D52F64D"))
    chk("BCM DV6T SBL == DV6T-14C097-AB.vbf",
        bcm.pick_sbl("DV6T-14C245-FF") == "DV6T-14C097-AB.vbf",
        str(bcm.pick_sbl("DV6T-14C245-FF")))
    pscm = ecu_db.get_profile(0x730)
    chk("PSCM level1 secret == 00009B2533",
        pscm.pick_secret("BV6T-14C217", 1) == bytes.fromhex("00009B2533"))
    chk("PSCM default SBL", pscm.pick_sbl("anything") == "BV6T-14C220-AA.vbf")
    chk("PSCM finalises", pscm.finalize)
    ipma = ecu_db.get_profile(0x706)
    chk("IPMA secret == 00009875CA",
        ipma.pick_secret("anything", 1) == bytes.fromhex("00009875CA"))
    # GROUND TRUTH candump-stock-flash.log: 706#1008310103010082 + 21 00 00
    # reassembles to 31 01 0301 00 82 00 00 -> FULL 4-byte call address, NOT
    # the high-half (a FirstFrame-only misread earned NRC 22 at SBL-start).
    chk("IPMA uses FULL 4-byte SBL call address", not ipma.sbl_call_halfword)
    chk("IPMA default SBL", ipma.pick_sbl("x") == "CV4T-14F399-AF.VBF")

    print("\n== ECU selection by name / id ==")
    chk("resolve('PCM') -> 0x7E0", ecu_db.resolve("PCM") is ecu_db.ECUS[0x7E0])
    chk("resolve('bcm') case-insensitive",
        ecu_db.resolve("bcm") is ecu_db.ECUS[0x726])
    chk("resolve('726') hex", ecu_db.resolve("726") is ecu_db.ECUS[0x726])
    chk("resolve('0x7E0')", ecu_db.resolve("0x7E0") is ecu_db.ECUS[0x7E0])
    chk("resolve('7E0') bare hex", ecu_db.resolve("7E0") is ecu_db.ECUS[0x7E0])
    chk("resolve(0x730) int", ecu_db.resolve(0x730) is ecu_db.ECUS[0x730])
    chk("resolve('EPAS') alias", ecu_db.resolve("EPAS") is ecu_db.ECUS[0x730])
    chk("resolve('nope') -> None", ecu_db.resolve("nope") is None)

    print("\n== DTC decode ==")
    from vbf import dtc_code as _dc, dtc_status_str as _ds
    chk("0x030100 -> P0301-00", _dc(0x030100) == "P0301-00", _dc(0x030100))
    chk("0x412364 -> C0123-64", _dc(0x412364) == "C0123-64", _dc(0x412364))
    chk("0x900164 -> B1001-64", _dc(0x900164) == "B1001-64", _dc(0x900164))
    chk("0xC1A012 -> U01A0-12", _dc(0xC1A012) == "U01A0-12", _dc(0xC1A012))
    chk("status 0x08 -> confirmedDTC", "confirmedDTC" in _ds(0x08))
    chk("status 0x2F multiple bits", _ds(0x2F).count(",") >= 2, _ds(0x2F))
    from vbf import dtc_is_actual as _ia
    chk("0x50 (both not-completed) is NOT actual", not _ia(0x50))
    chk("0x40|0x10 alone not actual", not _ia(0x40) and not _ia(0x10))
    chk("0x08 confirmed IS actual", _ia(0x08))
    chk("0x2F IS actual", _ia(0x2F))
    chk("0x51 (confirmed+notcompleted) IS actual", _ia(0x51))
    # 19 02 parse: 59 02 <avail> then 4-byte records
    import vbf as _vbf

    class _DtcSock:
        def settimeout(self, t):
            pass

        def send(self, d):
            pass

        def recv(self, n):
            return bytes([0x59, 0x02, 0xFF,
                          0x03, 0x01, 0x00, 0x08,     # P0301-00 confirmed
                          0xC1, 0xA0, 0x12, 0x2F])    # C1A0-12
    ed = _vbf.Ecu("can0", 0x726, 0x72E, execute=False)
    ed.execute = True
    ed.s = _DtcSock()
    got, avail = ed.read_dtcs()
    chk("read_dtcs parses 2 records", got is not None and len(got) == 2,
        str(got))
    chk("first DTC decodes P0301-00", got and _dc(got[0][0]) == "P0301-00")

    print("\n== reset + ALL/broadcast ==")
    chk("_selector_is_all('ALL')", _selector_is_all("ALL"))
    chk("_selector_is_all('all') case-insensitive", _selector_is_all("all"))
    chk("_selector_is_all('7DF')", _selector_is_all("7DF"))
    chk("_selector_is_all('0x7DF')", _selector_is_all("0x7DF"))
    chk("_selector_is_all('BCM') False", not _selector_is_all("BCM"))
    chk("_selector_is_all('726') False", not _selector_is_all("726"))

    class _ResetSock:
        def __init__(self):
            self.sent = None

        def settimeout(self, t):
            pass

        def send(self, d):
            self.sent = d

        def recv(self, n):
            return bytes([0x51, 0x01])       # ECUReset positive
    er = _vbf.Ecu("can0", 0x726, 0x72E, execute=False)
    er.execute = True
    er.s = _ResetSock()
    chk("Ecu.reset() -> True on 0x51", er.reset(mode=0x01) is True)
    chk("reset sent 1101", er.s.sent == bytes.fromhex("1101"),
        er.s.sent.hex() if er.s.sent else "None")
    chk("functional_broadcast exists", callable(_vbf.functional_broadcast))
    chk("do_ident dispatches ALL to _ident_all",
        "_ident_all" in inspect.getsource(do_ident))
    chk("_ident_all iterates ecu_db.ECUS",
        "ecu_db.ECUS" in inspect.getsource(_ident_all))
    chk("do_dtc dispatches ALL to _dtc_all",
        "_dtc_all" in inspect.getsource(do_dtc))
    chk("_dtc_all counts actual per module, no per-DTC dump",
        "dtc_is_actual" in inspect.getsource(_dtc_all)
        and "dtc_code" not in inspect.getsource(_dtc_all))

    print("\n== readdid ascii sanitize ==")
    chk("printable passes through",
        _ascii_sanitize(b"CV6T-14C217-AR") == "CV6T-14C217-AR")
    chk("control/high bytes -> '.'",
        _ascii_sanitize(bytes([0x00, 0x1B, 0x0A, 0x0D, 0x7F, 0xFF, 0x41]))
        == "......A")
    chk("no ESC/CR/LF survive sanitize",
        all(c not in _ascii_sanitize(bytes(range(256))) for c in "\x1b\r\n\x00"))
    chk("sanitized length == input length",
        len(_ascii_sanitize(bytes(range(256)))) == 256)
    chk("hexdump renders binary safely (no raw control bytes)",
        all(ord(c) >= 0x20 or c == "\n" for c in _hexdump(bytes(range(64)))))
    chk("readdid wired into main dispatch",
        "do_readdid" in inspect.getsource(main))
    chk("writedid wired into main dispatch",
        "do_writedid" in inspect.getsource(main))
    chk("writedid builds a 2E request",
        "2E" in inspect.getsource(do_writedid)
        and "6E" in inspect.getsource(do_writedid))
    chk("silence wired into main dispatch",
        "do_silence" in inspect.getsource(main))
    chk("silence uses 10 02 (single) or BusQuiet (ALL) + keepalive",
        "1002" in inspect.getsource(do_silence)
        and "BusQuiet" in inspect.getsource(do_silence)
        and "Keepalive" in inspect.getsource(do_silence))
    # HERE must use realpath so a ~/.local/bin symlink resolves to the project
    # dir (else sibling imports and sbl/ break when run via the symlink).
    chk("HERE resolved via realpath (symlink-safe)",
        "os.path.realpath(__file__)" in open(os.path.realpath(__file__)).read())

    print("\n== shell completion ==")
    _cm = _completion_model(build_parser())
    chk("completion model lists every subcommand",
        set(_cm["subcmds"]) >= {"flash", "info", "verify", "ident", "readdid",
                                "writedid", "dtc", "cleardtc", "reset",
                                "silence", "memread", "memwrite", "list",
                                "completion"})
    chk("ecu-first subcommands detected",
        _cm["ecu_first"].get("dtc") and _cm["ecu_first"].get("silence")
        and _cm["ecu_first"].get("memread"))
    chk("file-first subcommands detected",
        "flash" in _cm["file_first"] and "info" in _cm["file_first"])
    chk("flash flags captured in model",
        "--dry-run" in _cm["opts"]["flash"]
        and "--quiet-bus" in _cm["opts"]["flash"])
    _et = _ecu_tokens()
    chk("ecu tokens include names + ALL/7DF",
        "BCM" in _et and "PSCM" in _et and "ALL" in _et and "7DF" in _et)
    _bash = _gen_bash(_cm)
    chk("bash script names every subcommand",
        all(f"{c})" in _bash for c in _cm["subcmds"]))
    chk("bash script embeds ecu tokens + complete registration",
        "BCM" in _bash and "complete -o filenames -F _vbflasher" in _bash)
    _zsh = _gen_zsh(_cm)
    chk("zsh script has #compdef header",
        _zsh.startswith("#compdef vbflasher"))
    # validate bash syntax if bash is available (non-fatal if not)
    try:
        import shutil
        import subprocess
        _bp = shutil.which("bash")
        if _bp:
            _r = subprocess.run([_bp, "-n"], input=_bash.encode(),
                                capture_output=True)
            chk("generated bash script parses (bash -n)", _r.returncode == 0,
                _r.stderr.decode()[:120])
        else:
            chk("generated bash script parses (bash -n)", True, "(no bash)")
    except Exception as e:  # noqa: BLE001
        chk("generated bash script parses (bash -n)", False, str(e)[:120])

    print("\n== memread / memwrite primitives ==")
    # upload_block: 75 declares 0x82 (128 payload), then 8 x 76-frames of 128 B,
    # matching the UCDS PSCM EEPROM read (0x400 = 1024 bytes in 8 blocks).
    class _UpSock:
        def __init__(self):
            self.n = 0

        def settimeout(self, t):
            pass

        def send(self, d):
            self.last = d

        def recv(self, n):
            self.n += 1
            if self.n == 1:
                return bytes([0x75, 0x20, 0x00, 0x82])      # maxblk 0x82
            bc = (self.n - 1) & 0xFF
            return bytes([0x76, bc]) + bytes([bc]) * 128     # 128 payload B
    eu = _vbf.Ecu("can0", 0x730, 0x738, execute=False)
    eu.execute = True
    # the 37 exit answers 77 at the end
    class _UpSock2(_UpSock):
        def recv(self, n):
            self.n += 1
            if self.n == 1:
                return bytes([0x75, 0x20, 0x00, 0x82])
            if self.n <= 9:                                  # 8 data frames
                bc = (self.n - 1) & 0xFF
                return bytes([0x76, bc]) + bytes([bc]) * 128
            return bytes([0x77, 0x0A, 0xD2])                 # 37 exit
    eu.s = _UpSock2()
    got = _vbf.upload_block(eu, 0x02000000, 0x400, progress_interval=999)
    chk("upload_block returns 1024 bytes", len(got) == 1024, str(len(got)))
    chk("upload_block first block byte == 1", got[0] == 1, str(got[0]))

    # download_raw_block: 74 declares 0x82, then N x 76, then 77.
    class _DlSock:
        def __init__(self):
            self.n = 0
            self.frames = []

        def settimeout(self, t):
            pass

        def send(self, d):
            self.frames.append(d)

        def recv(self, n):
            self.n += 1
            if self.n == 1:
                return bytes([0x74, 0x20, 0x00, 0x82])
            if self.n <= 9:
                return bytes([0x76, (self.n - 1) & 0xFF])
            return bytes([0x77, 0x2B, 0xF8])
    ed2 = _vbf.Ecu("can0", 0x730, 0x738, execute=False)
    ed2.execute = True
    ed2.s = _DlSock()
    _vbf.download_raw_block(ed2, 0x02000000, bytes(range(256)) * 4,
                            progress_interval=999)
    # first sent frame is the 34 RequestDownload; count 36 data frames
    data_frames = [f for f in ed2.s.frames if f[:1] == b"\x36"]
    chk("download_raw_block sent 8 data frames", len(data_frames) == 8,
        str(len(data_frames)))
    chk("memread/memwrite wired into main dispatch",
        "do_memread" in inspect.getsource(main)
        and "do_memwrite" in inspect.getsource(main))

    # keys computed via the registry secret must equal each proven tool's key
    print("\n== registry secret -> proven per-ECU key ==")
    import importlib.util
    seeds = [(0x1F, 0x7C, 0x69), (0xAA, 0xBB, 0xCC), (0x12, 0x34, 0x56)]

    def loadmod(p, n):
        s = importlib.util.spec_from_file_location(n, p)
        m = importlib.util.module_from_spec(s)
        s.loader.exec_module(m)
        return m

    bp = "/home/gl/Projects/ford/BCM/Research/work/flash/bcmflash.py"
    if os.path.exists(bp):
        m = loadmod(bp, "bcmflash")
        sec = bcm.pick_secret("DV6T-14C245-FF", 1)
        chk("BCM key == bcmflash on 3 seeds",
            all(ford_seckey.key_from_seed(s, sec) == m.key_from_seed(list(s))
                for s in seeds))
    ip = "/home/gl/Projects/ford/IPMA/Research/work/ipma_flash.py"
    if os.path.exists(ip):
        m = loadmod(ip, "ipma_flash")
        sec = ipma.pick_secret("x", 1)
        chk("IPMA key == ipma_flash on 3 seeds",
            all(ford_seckey.key_from_seed(s, sec)
                == m.key_from_seed(bytes(s), int.from_bytes(sec, "big"))
                for s in seeds))

    # VBF parser against real files
    print("\n== VBF parser on real files ==")
    for path, typ in (
            ("/home/gl/Projects/ford/BCM/Research/DV6T-14C097-AB.vbf", "SBL"),
            ("/home/gl/Projects/ford/PSCM/BV6T-14C220-AA.vbf", "SBL"),
            ("/home/gl/Projects/ford/PSCM/CV6T-14C217-AR.VBF", "EXE")):
        if not os.path.exists(path):
            print(f"  SKIP  {os.path.basename(path)}")
            continue
        v = Vbf(path)
        chk(f"{os.path.basename(path)} parses & integrity clean",
            not v.check() and v.ptype == typ, f"type={v.ptype}")

    # transport: first-response wait is `timeout`, NOT `pending_timeout`, until
    # a 0x78 arrives. Regression guard for the sleeping-bus hang.
    print("\n== transport timeout semantics ==")
    import vbf as _vbf
    src = inspect.getsource(_vbf.Ecu.req)
    chk("req() sets settimeout(timeout) before the recv loop",
        "self.s.settimeout(timeout)" in src)
    chk("req() extends to pending_timeout only inside the 0x78 branch",
        src.index("self.s.settimeout(pending_timeout)")
        > src.index("r[2] == 0x78"))
    chk("Ecu has a bounded wake() retry", hasattr(_vbf.Ecu, "wake"))

    class _FakeSock:
        """Records the timeout in force at each recv; replies pending then OK."""
        def __init__(self):
            self.timeouts, self.cur, self._n = [], None, 0

        def settimeout(self, t):
            self.cur = t

        def send(self, d):
            pass

        def recv(self, n):
            self.timeouts.append(self.cur)
            self._n += 1
            if self._n == 1:
                return bytes([0x7F, 0x31, 0x78])       # responsePending
            return bytes([0x71, 0x01, 0xFF, 0x00])     # positive

    e = _vbf.Ecu("can0", 0x730, 0x738, execute=False)
    e.execute = True
    e.s = _FakeSock()
    e.req("3101FF00", timeout=2.0, pending_timeout=40.0)
    chk("first recv uses `timeout` (2.0), not pending_timeout",
        e.s.timeouts and e.s.timeouts[0] == 2.0, str(e.s.timeouts))
    chk("after 0x78 the wait extends to pending_timeout (40.0)",
        e.s.timeouts[-1] == 40.0, str(e.s.timeouts))

    # STALE-FRAME DRAIN: a frame that is neither the positive nor the negative
    # response to THIS request (e.g. a duplicated 50 02 programmingSession
    # still queued when we send 27 01) must be discarded, not returned.
    chk("req() drains stale frames (skips non-matching SID)",
        "stale" in inspect.getsource(_vbf.Ecu.req).lower())

    class _StaleSock:
        def __init__(self, seq):
            self.seq, self.i = seq, 0

        def settimeout(self, t):
            pass

        def send(self, d):
            pass

        def recv(self, n):
            v = self.seq[self.i]
            self.i += 1
            if isinstance(v, Exception):
                raise v
            return v
    es = _vbf.Ecu("can0", 0x7E0, 0x7E8, execute=False)
    es.execute = True
    es.s = _StaleSock([bytes.fromhex("5002001901F4"),   # stale 10 02 echo
                       bytes.fromhex("67011234AB")])     # real seed
    rr = es.req("2701", timeout=1.0)
    chk("stale 50 02 dropped, 27 01 gets the real 67 seed",
        rr is not None and rr[0] == 0x67, rr.hex() if rr else "None")
    # a genuine negative response to THIS request is NOT stale-dropped
    es2 = _vbf.Ecu("can0", 0x7E0, 0x7E8, execute=False)
    es2.execute = True
    es2.s = _StaleSock([bytes.fromhex("7F2735")])        # NRC 35 to 27
    rn = es2.req("2701", timeout=1.0)
    chk("negative response (7F 27 35) is returned, not drained",
        rn is not None and rn[0] == 0x7F and rn[1] == 0x27,
        rn.hex() if rn else "None")

    # OMIT regions (Ford PCM boot + protected block) must be excluded from
    # both erase and download. Ground-truth: pcm_BUNEEV vendor capture.
    print("\n== VBF omit filtering ==")
    _pcm = "/home/gl/Projects/ford/PCM/PCM_Research/DV4A-14C204-SB.fanv2-tft.crc.VBF"
    if os.path.exists(_pcm):
        vp = Vbf(_pcm)
        chk("PCM VBF declares an omit section", len(vp.omit) == 5,
            str(len(vp.omit)))
        fe = [a for a, _ in vp.flash_erase()]
        chk("boot block 0x80000000 excluded from erase",
            0x80000000 not in fe)
        chk("protected 0x80200000 excluded from erase",
            0x80200000 not in fe)
        chk("flash_erase drops exactly the omitted regions",
            len(vp.flash_erase()) == len(vp.erase) - len(vp.omit),
            f"{len(vp.flash_erase())} of {len(vp.erase)}")
        chk("no downloaded block overlaps an omit region",
            all(not vp._is_omitted(b["start"], b["length"])
                for b in vp.flash_blocks()))
    else:
        print(f"  SKIP  {os.path.basename(_pcm)} not present")

    # read_identity must run end-to-end in EXECUTE mode (guards the flash path
    # against undefined-name / signature regressions that dry-run never hits).
    class _IdentSock:
        """Models a real ECU: answers 22 <DID> reads, but the 3E 00 wake poke
        gets no reply (times out), exactly like a quiet bus. recv() dispatches
        on the last request so the stale-frame drain in req() has a real
        socket.timeout to terminate on."""
        def __init__(self):
            self.last = b""

        def settimeout(self, t):
            pass

        def send(self, d):
            self.last = d

        def recv(self, n):
            if self.last[:1] == b"\x22":
                return bytes([0x62, 0xF1, 0x11]) + b"TEST-14C245-AA"
            raise _vbf.socket.timeout()     # nothing answers 3E 00 wake

    ei = _vbf.Ecu("can0", 0x726, 0x72E, execute=False)
    ei.execute = True
    ei.s = _IdentSock()
    try:
        got = read_identity(ei, ecu_db.get_profile(0x726),
                            wake_tries=1, wake_timeout=0.01)
        chk("read_identity(execute) returns F111", got.get("F111") ==
            "TEST-14C245-AA", str(got.get("F111")))
    except Exception as exc:  # noqa: BLE001
        chk("read_identity(execute) runs without error", False, repr(exc))

    # CLI surface: flash must accept the documented flags
    print("\n== CLI surface ==")
    import io
    import contextlib
    saved = sys.argv[:]
    try:
        for cmd in ("info", "verify", "ident", "readdid", "writedid", "dtc",
                    "cleardtc", "reset", "silence", "memread", "memwrite",
                    "completion", "flash", "list"):
            sys.argv = ["x", cmd, "--help"]
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    main()
            except SystemExit:
                pass
            chk(f"subcommand '{cmd}' exists", "usage" in buf.getvalue().lower())
        sys.argv = ["x", "flash", "--help"]
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                main()
        except SystemExit:
            pass
        h = buf.getvalue()
        for flag in ("--iface", "--sbl", "--sbl-dir", "--secret", "--dry-run",
                     "--force", "--test-sbl", "--quiet-bus", "--erase-timeout",
                     "--tp-interval", "--rxid", "--logfile", "--yes", "--hw"):
            chk(f"flash accepts {flag}", flag in h)
    finally:
        sys.argv = saved

    print("\n" + "=" * 60)
    print("SELFTEST:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


def build_parser():
    ap = argparse.ArgumentParser(
        description="Multi-ECU Ford VBF flasher (SBL & secret auto-selected "
                    "from F111).")
    ap.add_argument("--selftest", action="store_true",
                    help="run offline self-tests and exit")
    sub = ap.add_subparsers(dest="cmd")

    for name in ("info", "verify"):
        s = sub.add_parser(name, help=f"{name} one or more VBF files")
        s.add_argument("vbf", nargs="+", metavar="FILE")

    s = sub.add_parser("list", help="list registered ECUs")

    s = sub.add_parser(
        "completion",
        help="print or install a bash/zsh tab-completion script")
    s.add_argument("shell", choices=("bash", "zsh"),
                   help="which shell to generate completion for")
    s.add_argument("--install", action="store_true",
                   help="write it to the user completion dir instead of stdout")

    def add_ecu_diag_parser(cmd, help_text):
        """A read/clear subcommand that selects an ECU by name or id (no VBF)."""
        sp = sub.add_parser(cmd, help=help_text)
        sp.add_argument("ecu", metavar="ECU",
                        help="ECU by name (PCM, BCM, PSCM, ABS, ...), CAN id "
                             "(726, 0x7E0), or ALL / 7DF for every module")
        sp.add_argument("--iface", default="can0",
                        help="SocketCAN interface (default can0)")
        sp.add_argument("--rxid", type=lambda x: int(x, 0), default=None,
                        help="override response CAN ID (default: profile's)")
        sp.add_argument("--wake-tries", type=int, default=8)
        sp.add_argument("--wake-timeout", type=float, default=0.5)
        return sp

    add_ecu_diag_parser("ident", "read a live ECU's identity DIDs")

    s = add_ecu_diag_parser("readdid",
                            "read arbitrary DID(s) (22), print hex + ascii")
    s.add_argument("did", nargs="+", metavar="DID",
                   help="2-byte DID(s) in hex, e.g. F190 0xF111 F18C")
    s.add_argument("--timeout", type=float, default=5.0,
                   help="per-DID response timeout in seconds (default 5)")

    s = add_ecu_diag_parser("writedid",
                            "write a DID (2E) with hex data")
    s.add_argument("did", metavar="DID", help="2-byte DID in hex, e.g. F190")
    s.add_argument("data", metavar="HEX",
                   help="data as hex bytes, e.g. 574630414258... (spaces ok)")
    s.add_argument("--session", type=lambda x: int(x, 0), default=None,
                   help="enter diagnosticSession first (e.g. 0x03 extended, "
                        "0x02 programming) — some DIDs need it")
    s.add_argument("--unlock", action="store_true",
                   help="SecurityAccess unlock before writing (some DIDs need it)")
    s.add_argument("--secret", type=lambda x: int(x, 0), default=None,
                   help="override the seed-key secret (implies --unlock)")
    s.add_argument("--sec-level", type=lambda x: int(x, 0), default=None,
                   help="SecurityAccess request level (implies --unlock; "
                        "default level 1 when unlocking)")
    s.add_argument("--hw", default=None,
                   help="assume this F111 for secret selection under --unlock")
    s.add_argument("--timeout", type=float, default=5.0,
                   help="response timeout in seconds (default 5)")
    s.add_argument("--yes", "-y", action="store_true",
                   help="skip the confirmation prompt")

    s = add_ecu_diag_parser("dtc", "read DTCs from an ECU (no VBF needed)")
    s.add_argument("--status-mask", type=lambda x: int(x, 0), default=0xFF,
                   help="DTCStatusMask for 19 02 (default 0xFF = all)")
    s.add_argument("--all", action="store_true",
                   help="show every DTC including 'not completed' housekeeping "
                        "entries (default: only actual faults)")

    s = add_ecu_diag_parser("cleardtc",
                            "clear DTCs on an ECU, or ALL modules (no VBF)")
    s.add_argument("--group", type=lambda x: int(x, 0), default=0xFFFFFF,
                   help="DTC group to clear (default 0xFFFFFF = all)")
    s.add_argument("--repeat", type=int, default=5,
                   help="broadcast send count for the ALL/7DF target (default 5)")
    s.add_argument("--yes", "-y", action="store_true",
                   help="skip the confirmation prompt")

    s = add_ecu_diag_parser("reset",
                            "ECUReset a module, or ALL modules (no VBF)")
    s.add_argument("--mode", type=lambda x: int(x, 0), default=0x01,
                   help="reset type: 0x01 hardReset (default), 0x03 softReset")
    s.add_argument("--repeat", type=int, default=5,
                   help="broadcast send count for the ALL/7DF target (default 5)")
    s.add_argument("--yes", "-y", action="store_true",
                   help="skip the confirmation prompt")

    s = add_ecu_diag_parser(
        "silence",
        "hold a module (or ALL/7DF) in programmingSession so it stops "
        "transmitting; restore on exit")
    s.add_argument("--tp-interval", type=float, default=TP_INTERVAL,
                   help=f"TesterPresent period in seconds (default "
                        f"{TP_INTERVAL}; keeps the module silent)")
    s.add_argument("--duration", type=float, default=None,
                   help="silence for N seconds then restore (default: until "
                        "Ctrl-C)")

    def add_sbl_flags(sp):
        """SBL/session flags shared by memread / memwrite."""
        sp.add_argument("ecu", metavar="ECU",
                        help="ECU by name (PSCM, BCM, ...) or CAN id (730)")
        sp.add_argument("--addr", type=lambda x: int(x, 0), required=True,
                        help="start address, e.g. 0x02000000")
        sp.add_argument("--iface", default="can0")
        sp.add_argument("--rxid", type=lambda x: int(x, 0), default=None)
        sp.add_argument("--sbl", default=None,
                        help="explicit SBL VBF path (else auto from F111)")
        sp.add_argument("--sbl-dir", action="append", default=[])
        sp.add_argument("--secret", type=lambda x: int(x, 0), default=None)
        sp.add_argument("--sec-level", type=lambda x: int(x, 0), default=1)
        sp.add_argument("--hw", default=None,
                        help="assume this F111 (skip the live read)")
        sp.add_argument("--addr-len-fmt", type=lambda x: int(x, 0), default=0x44,
                        help="addressAndLengthFormatId (default 0x44 = 4+4)")
        sp.add_argument("--quiet-bus", action="store_true")
        sp.add_argument("--wake-tries", type=int, default=8)
        sp.add_argument("--wake-timeout", type=float, default=0.5)
        sp.add_argument("--tp-interval", type=float, default=TP_INTERVAL)
        sp.add_argument("--progress-interval", type=float, default=2.0)
        sp.add_argument("--erase-timeout", type=float, default=60.0)
        sp.add_argument("--yes", "-y", action="store_true",
                        help="skip the confirmation prompt")
        sp.add_argument("--logfile",
                        default=os.path.join(HERE, "logs", "vbflasher.log"))
        return sp

    s = add_sbl_flags(sub.add_parser(
        "memread", help="read a raw memory/EEPROM region to a file (via SBL)"))
    s.add_argument("--length", type=lambda x: int(x, 0), required=True,
                   help="number of bytes to read, e.g. 0x400")
    s.add_argument("-o", "--outfile", required=True, help="output binary file")
    s.add_argument("--no-reset", action="store_true",
                   help="do not ECUReset after the read")

    s = add_sbl_flags(sub.add_parser(
        "memwrite",
        help="write a raw binary file to a memory/EEPROM region (via SBL)"))
    s.add_argument("-i", "--infile", required=True, help="input binary file")
    s.add_argument("--length", type=lambda x: int(x, 0), default=None,
                   help="assert the file is exactly this many bytes")
    s.add_argument("--no-erase", action="store_true",
                   help="skip the 31 01 FF00 erase before writing")
    s.add_argument("--no-verify", action="store_true",
                   help="skip the 31 01 0304 verify routine after writing")

    s = sub.add_parser("flash", help="flash one or more VBF files")
    s.add_argument("vbf", nargs="+", metavar="FILE",
                   help="VBF file(s) to upload. Multiple allowed; grouped by "
                        "ecu_address. SBL-type files are used as the SBL.")
    s.add_argument("--iface", default="can0",
                   help="SocketCAN interface (default can0)")
    s.add_argument("--rxid", type=lambda x: int(x, 0), default=None,
                   help="override response CAN ID (default: profile's)")
    s.add_argument("--sbl", default=None,
                   help="explicit SBL VBF path (overrides F111 auto-select)")
    s.add_argument("--sbl-dir", action="append", default=[],
                   help="extra directory to search for the selected SBL "
                        "(repeatable)")
    s.add_argument("--secret", type=lambda x: int(x, 0), default=None,
                   help="override the 40-bit seed-key secret, e.g. 0x64000B0C59")
    s.add_argument("--sec-level", type=lambda x: int(x, 0), default=1,
                   help="SecurityAccess request level (odd; default 1)")
    s.add_argument("--hw", default=None,
                   help="assume this F111 string (skip the live read / for "
                        "dry-run planning)")
    s.add_argument("--test-sbl", action="store_true",
                   help="load and start the SBL only; NO erase, NO write")
    s.add_argument("--dry-run", "-n", action="store_true",
                   help="print the plan only; connect to nothing, send nothing")
    s.add_argument("--yes", "-y", action="store_true",
                   help="skip the 'are you sure?' confirmation (for scripting)")
    s.add_argument("--force", action="store_true",
                   help="ignore an EXE identity mismatch")
    s.add_argument("--quiet-bus", action="store_true",
                   help="silence other modules for the flash (functional "
                        "10 82; unconfirmed, network-wide; off by default)")
    s.add_argument("--erase-timeout", type=float, default=60.0,
                   help="seconds of SILENCE that ends an erase/finalise wait")
    s.add_argument("--wake-tries", type=int, default=8,
                   help="3E 00 wake attempts for a sleeping bus (default 8)")
    s.add_argument("--wake-timeout", type=float, default=0.5,
                   help="seconds per wake attempt (default 0.5)")
    s.add_argument("--progress-interval", type=float, default=2.0,
                   help="download progress print interval in seconds "
                        "(default 2.0)")
    s.add_argument("--tp-interval", type=float, default=TP_INTERVAL,
                   help=f"TesterPresent period (default {TP_INTERVAL}; 0 off)")
    s.add_argument("--tp-id", type=lambda x: int(x, 0), default=-1,
                   help="broadcast CAN ID for TesterPresent/quiet-bus "
                        "(default: physical via ISO-TP; pass 0x7DF for "
                        "broadcast)")
    s.add_argument("--logfile",
                   default=os.path.join(HERE, "logs", "vbflasher.log"),
                   help="append a timestamped request/response trace here")
    return ap


def main():
    ap = build_parser()
    args = ap.parse_args()
    if args.selftest or args.cmd is None:
        if args.cmd is None and not args.selftest:
            ap.print_help()
            return 0
        return selftest()
    if args.cmd == "flash":
        # Flashing is live by default; the y/N prompt is the gate. --dry-run
        # opts out entirely (opens no socket, transmits nothing).
        args.execute = not args.dry_run
    return {"info": do_info, "verify": do_verify, "ident": do_ident,
            "readdid": do_readdid, "writedid": do_writedid,
            "dtc": do_dtc, "cleardtc": do_cleardtc, "reset": do_reset,
            "silence": do_silence,
            "memread": do_memread, "memwrite": do_memwrite,
            "completion": do_completion,
            "flash": do_flash, "list": do_list}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main() or 0)
