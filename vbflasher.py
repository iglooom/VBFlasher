#!/usr/bin/env python3
"""VBFlasher — a multi-ECU Ford VBF flasher.

One CLI flashes any registered Ford ECU. The target ECU, its SecurityAccess
secret and its Secondary Bootloader are chosen automatically from the module's
own F111 (hardware / Core Assembly Number) DID, exactly as the OEM-derived
FoCCCus tool does. Extend it by adding an EcuProfile to ecu_db.py — nothing in
this file hardcodes an ECU.

WHAT IT DOES, IN ORDER
  1. Parse and fully verify EVERY VBF given (block CRC-16 + file CRC-32).
     A corrupt file is refused before the ECU is touched, unless --force.
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
  python3 vbflasher.py ident   0x730 [--iface IFACE]
  python3 vbflasher.py flash   APP.vbf CAL.vbf [...] [--iface IFACE]
  python3 vbflasher.py flash   APP.vbf --dry-run          # plan only, no bus
  python3 vbflasher.py flash   APP.vbf --test-sbl         # load+run SBL only
"""
import argparse
import inspect
import os
import re
import socket
import sys
import threading
import time

# realpath (not abspath) so a symlink in ~/.local/bin resolves back to the real
# project dir — sibling modules (ecu_db, vbf) and sbl/ live next to the script.
HERE = os.path.dirname(os.path.realpath(__file__))
SBL_DIR = os.path.join(HERE, "sbl")   # default location for SBL VBF files
sys.path.insert(0, HERE)

import ecu_db                                            # noqa: E402
import ford_seckey                                       # noqa: E402
from vbf import (Vbf, Ecu, BusQuiet, Keepalive, FlashProgress, download_blocks,  # noqa: E402
                 human, fmt, iface_is_up, dtc_code, dtc_status_str,
                 dtc_is_actual, functional_broadcast,
                 upload_block, download_raw_block, erase_region,
                 verify_routine)

TP_INTERVAL = 1.5

# Pause between entering a diagnostic session and 27 xx requestSeed, for EVERY
# module. A Ford module that answers 50 02 jumps into its primary bootloader and
# needs a moment to come up; the first requestSeed sent too early can time out or
# be refused even though the identical request succeeds moments later. UCDS waits
# ~1.0 s here (CCM/GV6T/ucds_flash.log: 50 02 at t=9.111, 27 01 at t=10.129), so
# match it rather than the 0.1 s we used to use. Cost is one second per flash.
SEED_DELAY = 1.0


def settle_before_seed(delay=SEED_DELAY):
    """Wait out the post-session bootloader settle before requestSeed."""
    if delay > 0:
        print(f"   settling {delay:.1f}s before requestSeed "
              f"(module may still be entering its bootloader)")
        time.sleep(delay)


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
    labels = {"F188": "application sw (F188)", "F120": "application sw #2 (F120)",
              "F124": "calibration (F124)", "F125": "calibration #2 (F125)",
              "F108": "signal configuration (F108)",
              "F10A": "ECU cal-config part (F10A)",
              "F111": "hardware/Core Assembly (F111)",
              "F113": "core assembly (F113)", "F18C": "ECU serial (F18C)",
              "F190": "VIN (F190)", "F91": "ext hardware (F191)"}
    reasons = {}
    for did in profile.ident_dids:
        val = ecu.read_did(did)
        ident[did] = val
        why = ecu.last_did_status
        if why:
            reasons[did] = why
        # Report WHY a DID is blank. A module that answers `7F 22 21
        # busyRepeatRequest` to every ident is ALIVE and refusing, not absent —
        # printing a bare "-" for both makes a recoverable module look dead.
        print("   %-32s %s" % (labels.get(did, did),
                               val if val else f"-   ({why})" if why else "-"))
    if not any(ident.values()) and reasons:
        refused = [d for d, w in reasons.items() if w.startswith("refused")]
        if refused:
            print(f"   NOTE: the ECU ANSWERED every ident read with a negative "
                  f"response ({len(refused)}/{len(reasons)} DIDs) — it is alive "
                  f"on the bus, not absent.")
            print("         A module sitting in its bootloader, or busy, "
                  "cannot report identity but can still be flashed.")
            print("         Pass --hw <F111 string> to choose the SBL/secret "
                  "manually, or --sbl /path/to/SBL.vbf.")
        else:
            print("   NOTE: no ident DID answered at all — check the "
                  "interface, the CAN IDs and that the module is powered.")
    return ident


def part_family(p):
    """'EJ7T-14C088-AH' -> '14C088'; None when it is not a Ford part number.

    The middle field is the FUNCTION of the part (which software slot it
    fills); the prefix is the platform and the suffix the revision.
    """
    if not p:
        return None
    m = re.match(r"^[A-Z0-9]+-([A-Z0-9]+)-[A-Z0-9]+$", p.strip().upper())
    return m.group(1) if m else None


# Ident DIDs that carry SOFTWARE part numbers and may therefore be used as a
# flash gate. F111/F113 are HARDWARE (a hardware part can never equal a VBF's
# software part number — gating on one refuses every legitimate flash), F18C is
# a serial and F190 the VIN.
SW_IDENT_DIDS = ("F188", "F120", "F124", "F125", "F108", "F10A")


def resolve_gate_did(vbf, ident, profile):
    """Pick the ident DID that this VBF actually replaces, and judge it.

    Returns (did, live_value, verdict) where verdict is one of:
      'exact'  - the ECU already reports this exact part number
      'family' - same software slot, different revision: the normal upgrade
      'nomatch'- no DID carries this part family: probably the wrong file

    WHY NOT sw_part_type: a Ford IPC carries FOUR software parts across four
    DIDs (observed on the bench cluster: F188=EJ7T-14C026-AK,
    F120=EJ7T-14C026-BH, F124=EJ7T-14C088-AH, F125=EJ7T-14C088-BH) but a VBF
    only declares EXE or DATA. The static EXE->F188 map therefore compared a
    14C088 part against the 14C026 DID and refused a perfectly valid flash,
    which --force then papered over. The part-number FAMILY says which slot a
    file belongs in, so resolve the DID from the data instead of guessing from
    the type.
    """
    fam = part_family(vbf.part)
    if fam:
        # Prefer an exact hit, then any DID in the same family.
        cands = [(d, ident.get(d)) for d in SW_IDENT_DIDS if ident.get(d)]
        for d, val in cands:
            if val.strip().upper() == (vbf.part or "").strip().upper():
                return d, val, "exact"
        for d, val in cands:
            if part_family(val) == fam:
                return d, val, "family"
        if cands:
            return None, None, "nomatch"
    # No usable identity (dead/refusing module, or an unparseable part
    # number): fall back to the static map and let the caller report it.
    did = profile.ident_did_by_type.get(vbf.ptype, "F188")
    return did, ident.get(did), "unknown"


# --------------------------------------------------------------------------
# one ECU session (may hold several VBFs)
# --------------------------------------------------------------------------
def _is_virtual_map(v):
    """True if this VBF's block addresses are NOT a linear flash memory map.

    Ford/Volvo "Jade" parts (the QNX-based IPC, ecu_address 0x720) do not
    address flash at all: the header documents a `virtual_start_address =
    0x30000000` plus a `files_to_download` list of virtual lookup indices, and
    the body is a stream of alternating 4-byte index writes at 0x3FFFFFFC and
    payload blobs at 0x30000000. Both addresses REPEAT dozens of times inside
    one file (EJ7T-14C088-AH: 66 blocks at 0x3FFFFFFC, 4 at 0x30000000), which
    a real linear image can never do — writing the same address twice in one
    part would mean the part overwrites itself.

    That repetition is therefore the detector, and it is also why the
    interval bookkeeping in _check_flash_order() is meaningless for such a
    part: every Jade file "erases" the 4-byte index cell 0x3FFFFFFC that every
    other Jade file "writes", so ANY ordering of two of them looks fatal. The
    real serialisation for these parts is the on-target post_download.sh
    script, not the VBF address map.
    """
    starts = [b["start"] for b in v.flash_blocks()]
    return len(starts) != len(set(starts))


def _wire_blocks_for(v, args):
    """The blocks to download for `v` under the current options, with the
    blank-skip PROVEN lossless before it is allowed to change anything.

    Plan and execute both go through here so the dry run can never describe a
    different transfer from the one that happens.
    """
    dec = getattr(args, "decompress", False)
    skip = getattr(args, "skip_blank", 0)
    bb = getattr(args, "blank_byte", 0xFF)
    if skip and bb != 0xFF:
        raise SystemExit("--blank-byte must be 0xFF for blank skipping: "
                         "an erased flash gap reads as 0xFF")
    if not skip:
        return v.flash_blocks(decompress=dec), 0
    # A compressed container keeps its dfi 0x10 wire format: expand, split off
    # the erased-blank padding, then RE-PACK each fragment. --decompress stays
    # the explicit opt-out for a boot loader that cannot decompress.
    rec = v.compressed() and not dec
    probs = v.verify_blank_skip(decompress=dec, skip_blank=skip, blank_byte=bb,
                                recompress=rec)
    if probs:
        raise SystemExit(
            f"--skip-blank is not lossless for {os.path.basename(v.path)}:\n   "
            + "\n   ".join(probs)
            + "\n   Refusing to flash a partial image. Drop --skip-blank.")
    blocks = v.flash_blocks(decompress=dec, skip_blank=skip, blank_byte=bb,
                            recompress=rec)
    sent = sum(b["length"] for b in blocks)
    # Compare against what this option set would otherwise put on the wire:
    # the on-disk compressed bytes when re-packing, else the plain payload.
    full = (sum(b["length"] for b in v.flash_blocks())
            if rec else sum(b["length"] for b in v.flash_blocks(decompress=dec)))
    return blocks, full - sent


def _check_flash_order(to_flash, force=False):
    """Refuse an ordering where a later part's ERASE wipes an earlier part's
    freshly written blocks.

    GROUND TRUTH (ford/GWM/ucds_gwm_flash.log): the GWM's EXE part erases
    0x00008000 +0x38000 (224 KiB) while its SIGCFG part loads at 0x00008000 —
    i.e. the application erase covers the whole signal-configuration area. UCDS
    therefore sends EXE first and SIGCFG second. Given the two files in the
    other order this tool would erase away the SIGCFG it had just written and
    leave the module with a blank config, with nothing on the bus indicating a
    failure. Ordering is the operator's to fix, so name the offenders.

    Parts whose addresses are virtual rather than physical (see
    _is_virtual_map) are excluded from the bookkeeping entirely — checking them
    produces a guaranteed false positive, not safety.

    `force` downgrades a real overlap to a printed warning. It exists because
    this guard models the address map, and a map it models wrongly must not be
    able to block a flash outright; it is NOT a reason to skip thinking about
    the order.
    """
    written = []                                    # [(name, start, end)]
    for v in to_flash:
        name = os.path.basename(v.path)
        if _is_virtual_map(v):
            print(f"   note: {name} uses virtual (non-flash) block addresses; "
                  f"excluded from the flash-order check")
            continue
        for a, l in v.flash_erase():
            for pname, ps, pe in written:
                if a < pe and ps < a + l:
                    msg = (f"{name} erases 0x{a:08X}..0x{a + l:08X}, which "
                           f"covers blocks already written by {pname} "
                           f"(0x{ps:08X}..0x{pe:08X}). Put {name} BEFORE "
                           f"{pname} on the command line.")
                    if force:
                        print(f"   WARNING (--force): flash order would "
                              f"destroy data: {msg}")
                        continue
                    raise SystemExit(
                        f"flash order would destroy data: {msg} "
                        f"Use --force to flash in this order anyway.")
        # The on-wire length may be LZSS-compressed, but the ECU writes the
        # expanded bytes at these addresses. Compare against that flash span.
        for b in v.flash_blocks(decompress=True):
            written.append((name, b["start"], b["start"] + b["length"]))


def _check_integrity(vbfs, force=False):
    """Verify every VBF (block CRC-16 + file CRC-32) before the ECU is touched.

    A mismatch normally aborts: transmitting a file whose own checksums do not
    describe its contents is how a module ends up with an image neither the
    tool nor the ECU can account for.

    `force` downgrades a mismatch to a loud warning, for the one legitimate
    case: a DELIBERATELY modified file (a patched calibration, a hand-edited
    block) whose CRC fields were not recomputed. Hand-patched images that the
    ECU itself will checksum can still be rejected at finalise (31 01 0304) or
    simply refuse to run, so this says the file is intentional — not that it
    is sound.
    """
    bad = []
    for v in vbfs:
        print(v.describe())
        probs = v.check()
        if not probs:
            print("   integrity   OK (block CRC-16 + file CRC-32)\n")
            continue
        if force:
            print("   !! INTEGRITY FAILURE — flashing anyway (--force):")
            for p in probs:
                print("      " + p)
            print("      The file's own CRCs do not match its contents. The "
                  "ECU may reject\n      it at finalise or boot a broken "
                  "image. Only proceed if you edited\n      this file on "
                  "purpose.\n")
            continue
        print("   !! INTEGRITY FAILURE — refusing to transmit:")
        for p in probs:
            print("      " + p)
        bad.append(os.path.basename(v.path))
    if bad:
        raise SystemExit(
            f"integrity check failed for {', '.join(bad)}. Fix the file (or "
            f"recompute its CRCs); use --force to transmit it as-is.")


def enter_programming_session(ecu, args):
    """Catch a briefly available PBL with repeated physical 10 02 requests.

    Normal flashes retain their bounded wake retry. Recovery intentionally
    waits until a positive answer (or Ctrl-C), with no other diagnostic probes
    before the session request.
    """
    r = None
    attempts = 0
    while args.recovery or attempts < args.wake_tries:
        attempts += 1
        try:
            r = ecu.req("1002", timeout=0.2 if args.recovery else 1.0,
                        pending_timeout=0.2 if args.recovery else 30.0,
                        busy_retries=0 if args.recovery else 5,
                        what=f"10 02 programmingSession {attempts}")
        except TimeoutError:
            if not args.recovery:
                raise
            # ISO-TP can time out in send() while the ECU is unpowered;
            # Ecu.req() only turns recv() timeouts into None.
            r = None
        if r is not None and len(r) >= 2 and r[:2] == b"\x50\x02":
            profile = ecu_db.get_profile(ecu.txid) if args.recovery else None
            want = profile.recovery_session_response if profile else None
            if want is not None and r != want:
                if attempts == 1 or attempts % 25 == 0:
                    print(f"   50 02 from non-PBL responder ({fmt(r)}); "
                          "waiting for power-cycle", flush=True)
                time.sleep(0.02)
                continue
            print(f"   OK   10 02 programmingSession        {fmt(r)} "
                  f"(attempt {attempts})")
            return
        if args.recovery:
            if attempts == 1 or attempts % 25 == 0:
                print(f"   waiting for PBL: {attempts} attempts, "
                      f"last response {fmt(r)} (Ctrl-C to stop)", flush=True)
            time.sleep(0.02)
        else:
            time.sleep(0.1)
    raise SystemExit(f"10 02 programmingSession: {fmt(r)} "
                     f"(no session after {attempts} tries)")


def check_finalize_response(profile, response):
    """Do not confuse a positive RoutineControl SID with an accepted image."""
    expected = profile.finalize_response
    if expected is not None and response != expected:
        raise SystemExit(
            f"{profile.name}: finalise answered {fmt(response)}, expected "
            f"{fmt(expected)} (status 10 02 = accepted for boot). "
            "Do not treat this flash as successful or reset into it.")


def flash_session(txid, files, args):
    profile = ecu_db.get_profile(txid)
    if profile is None:
        raise SystemExit(
            f"ecu_address 0x{txid:03X} is not in the registry (ecu_db.py). "
            f"Add an EcuProfile for it.")
    rxid = args.rxid if args.rxid is not None else profile.resp_id()
    iface = _profile_iface(profile, args.iface)

    vbfs = [Vbf(f) for f in files]
    # SBL parts among the given files are loaded as the SBL, not flashed to app.
    print("=" * 72)
    print(f"TARGET  {profile.name}   tx=0x{txid:03X} rx=0x{rxid:03X}   "
          f"bus={profile.bus} iface={iface}")
    print("=" * 72)
    _check_integrity(vbfs, force=args.force)

    # order: non-SBL application/data parts get flashed; erase-bearing first
    to_flash = [v for v in vbfs if v.ptype != "SBL"]
    if not to_flash and not args.test_sbl:
        raise SystemExit("no flashable (non-SBL) VBF given; use --test-sbl to "
                         "just load an SBL.")
    _check_flash_order(to_flash, force=args.force)

    if args.execute:
        up = iface_is_up(iface)
        if up is False:
            raise SystemExit(f"interface {iface} is DOWN. Bring it up "
                             f"first (e.g. sudo ip link set {iface} up).")
        if up is None and not os.path.exists(f"/sys/class/net/{iface}"):
            raise SystemExit(f"interface {iface} does not exist. Check "
                             f"`ip link` or pass --iface.")

    # --- connect + identity (needs the live F111 to choose SBL/secret) -----
    logf = None
    if args.logfile:
        os.makedirs(os.path.dirname(args.logfile) or ".", exist_ok=True)
        logf = open(args.logfile, "a")
        logf.write(f"\n==== {time.strftime('%F %T')} {profile.name} "
                   f"tx=0x{txid:03X} rx=0x{rxid:03X} ====\n")

    ecu = Ecu(iface, txid, rxid, execute=args.execute, logfile=logf)

    hw = args.hw or ""
    ident = {}
    if args.execute and args.recovery:
        # The PBL may only accept requests briefly after power-up. Do not
        # spend that window waking the bus or reading identity DIDs first.
        print("\n== recovery: skipping live identity reads ==")
        print("   Power-cycle the ECU after the prompt; waiting for 10 02.")
    elif args.execute:
        ident = read_identity(ecu, profile, args.wake_tries, args.wake_timeout)
        hw = args.hw or ident.get("F111") or ""
        if not hw and not args.sbl:
            raise SystemExit(
                "could not read F111 from the ECU and no --hw/--sbl given; "
                "cannot choose the SBL/secret.\n"
                "    If the ECU is answering with negative responses (see "
                "above) it is alive and flashable —\n"
                "    it just cannot report its identity. Pass --hw <F111> or "
                "--sbl /path/to/SBL.vbf.\n"
                "    Known F111 prefixes for this ECU: "
                + (", ".join(sorted({r.hw_prefix or "(any)"
                                     for r in profile.secrets}))
                   or "(none registered)"))
    else:
        print("\n== current firmware / identity ==")
        if args.recovery:
            print("   [recovery dry run] live F111 reads are skipped; supply "
                  "--hw or explicit --sbl and --secret for a live run.")
        else:
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
    if args.recovery:
        print("   MODE         --recovery: skip identity/wake probes; repeatedly "
              "send 10 02 until the ECU answers (Ctrl-C to stop).")
        print("   WARNING      live software identity cannot be checked; "
              "verify the target and VBF yourself before confirming.")
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
                print("      ERASE (none declared in the header)")
                if re.search(r"//.*erase\s*=", v.header_text):
                    print("            note: the header's erase block is "
                          "COMMENTED OUT — deliberately not sent.")
                    print("            (sending it earns NRC 31 "
                          "requestOutOfRange from the SBL)")
            if omitted:
                print(f"      OMIT  {len(omitted)} protected region(s) "
                      f"(not erased/written):")
                for a, l in omitted:
                    print(f"         0x{a:08X}  len 0x{l:06X} ({human(l)})")
            wblocks, saved = _wire_blocks_for(v, args)
            wpayload = sum(b["length"] for b in wblocks)
            dfi = v.wire_dfi(args.decompress)
            recomp = v.compressed() and not args.decompress and args.skip_blank
            if v.compressed():
                if args.decompress:
                    print(f"      WRITE {len(wblocks)} block(s), "
                          f"{human(wpayload)} "
                          f"(--decompress: LZSS expanded on the host, sent "
                          f"PLAIN as 34 {dfi:02X}):")
                elif recomp:
                    print(f"      WRITE {len(wblocks)} block(s), "
                          f"{human(wpayload)} "
                          f"(LZSS re-packed on the host after blank-skipping, "
                          f"sent COMPRESSED as 34 {dfi:02X}; the ECU unpacks):")
                else:
                    print(f"      WRITE {len(wblocks)} block(s), "
                          f"{human(wpayload)} "
                          f"(LZSS, sent verbatim as 34 {dfi:02X}; the ECU "
                          f"unpacks):")
            else:
                print(f"      WRITE {len(wblocks)} block(s), {human(wpayload)}:")
            if saved:
                print(f"      --skip-blank 0x{args.skip_blank:X}: "
                      f"{human(saved)} less on the wire "
                      f"({100.0 * saved / (wpayload + saved):.0f}% of "
                      + ("the compressed stream" if recomp else
                         f"0x{args.blank_byte:02X} padding")
                      + ", verified lossless by reassembly)")
            for b in wblocks:
                if recomp:
                    print(f"         -> 0x{b['start']:08X}  "
                          f"{human(b['length'])} compressed "
                          f"({human(b['plain_length'])} written)")
                else:
                    print(f"         -> 0x{b['start']:08X}  "
                          f"{human(b['length'])}")
            gate = profile.ident_did_by_type.get(v.ptype, "F188")
            if ident:
                gdid, live, verdict = resolve_gate_did(v, ident, profile)
                if verdict == "exact":
                    print(f"      identity: already on the ECU as "
                          f"{gdid}={live} (re-flash of the same part)")
                elif verdict == "family":
                    print(f"      identity gate: replaces {gdid}={live} "
                          f"(same family {part_family(v.part)})")
                elif verdict == "nomatch":
                    print(f"      identity gate: NO DID carries family "
                          f"{part_family(v.part)} — wrong file for this module?")
                else:
                    print(f"      identity: {gate} (unverified)")
            else:
                print(f"      identity gate: resolved from the part family "
                      f"at flash time (dry run — ECU not read)")
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
        for v in (to_flash if to_flash else [sbl]):
            print(f"SHA-256 {os.path.basename(v.path)}: {v.sha256()[:8]}...")
        ans = input("Are you sure you want to proceed? [y/N] ").strip().lower()
        if ans != "y":
            print("aborted by user.")
            if logf:
                logf.close()
            return

    # --- execute -----------------------------------------------------------
    tp_bcast = args.tp_id if args.tp_id >= 0 else FUNCTIONAL_ID
    quiet = BusQuiet(iface, tp_bcast, execute=True, enabled=args.quiet_bus)
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
    progress = FlashProgress(
        sum(b["length"] for b in sbl.wire_blocks(args.decompress))
        + sum(sum(b["length"] for b in _wire_blocks_for(v, args)[0])
              for v in ([] if args.test_sbl else to_flash)),
        interval=args.progress_interval)
    try:
        progress.start()
        quiet.arm()

        # Identity gate. Resolve WHICH DID a file replaces from its part-number
        # family rather than from sw_part_type — an IPC carries several
        # software parts and the type alone names the wrong DID (see
        # resolve_gate_did). Only a file whose family matches NO DID on the
        # module is refused; a same-family revision change is a normal flash.
        for v in to_flash:
            gdid, live, verdict = resolve_gate_did(v, ident, profile)
            if verdict == "exact":
                print(f"   {v.part}: already on the ECU as {gdid} "
                      f"(re-flashing the same part)")
            elif verdict == "family":
                print(f"   {v.part}: replaces {gdid}={live} "
                      f"(same part family)")
            elif verdict == "nomatch":
                msg = (f"no software DID on this ECU carries part family "
                       f"{part_family(v.part)} (file {os.path.basename(v.path)}"
                       f", part {v.part}). The module reports: "
                       + ", ".join(f"{d}={ident[d]}" for d in SW_IDENT_DIDS
                                   if ident.get(d))
                       + ". This is probably the wrong file for this module.")
                if args.force:
                    print(f"   WARNING (--force): {msg}")
                else:
                    raise SystemExit(f"identity mismatch: {msg} "
                                     f"Use --force to flash it anyway.")
            else:
                print(f"   {v.part}: identity unverified "
                      f"(no readable software DID); proceeding")

        print("\n== session + security ==")
        enter_programming_session(ecu, args)
        # Settle before requestSeed on EVERY module (see SEED_DELAY). The one
        # exception is --recovery: the skill's recovery procedure continues
        # immediately once the PBL answers, so it keeps the short wait.
        if not args.recovery:
            settle_before_seed(args.seed_delay)
        else:
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

        progress.stage_name("SBL -> RAM")
        print("\n== SBL -> RAM ==")
        download_blocks(ecu, sbl.wire_blocks(args.decompress),
                        "sbl", args.progress_interval,
                        dfi=sbl.wire_dfi(args.decompress),
                        progress=progress if progress.enabled else None,
                        exit_crc=profile.transfer_exit_crc, force=args.force)
        if profile.sbl_call_halfword:
            call_arg = f"{(sbl.call >> 16) & 0xFFFF:04X}"
        else:
            call_arg = f"{sbl.call:08X}"
        r = ecu.expect("31010301" + call_arg, 0x71, "31 01 0301 start SBL",
                       timeout=10.0)
        if profile.sbl_start_response is not None and r != profile.sbl_start_response:
            raise SystemExit(
                f"SBL start answered {fmt(r)}, not the proven PBL response "
                f"{fmt(profile.sbl_start_response)}. The application may have "
                "answered without starting the SBL; refusing to erase. "
                "Use --recovery and power-cycle the ECU to catch the PBL.")
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
                progress.stage_name("erase")
                print(f"\n== erase for {os.path.basename(v.path)} "
                      f"({len(erase)} region"
                      + (f", {skipped} omitted" if skipped else "") + ") ==")
                import struct as _s
                for a, l in erase:
                    ecu.expect("3101FF00" + _s.pack(">I", a).hex()
                               + _s.pack(">I", l).hex(), 0x71,
                               f"erase 0x{a:08X}", timeout=15.0,
                               pending_timeout=args.erase_timeout)
                progress.stage_name("download")
                print(f"\n== download {os.path.basename(v.path)} ==")
                dblocks, dsaved = _wire_blocks_for(v, args)
                if dsaved:
                    print(f"   --skip-blank: {len(dblocks)} fragment(s), "
                          f"{human(dsaved)} of blank padding skipped")
                download_blocks(ecu, dblocks, v.part or "app",
                                args.progress_interval,
                                dfi=v.wire_dfi(args.decompress),
                                progress=progress if progress.enabled else None,
                                exit_crc=profile.transfer_exit_crc,
                                force=args.force)

            if profile.finalize:
                progress.stage_name("finalise")
                print("\n== finalise (31 01 0304) ==")
                response = ecu.expect("31010304", 0x71, "31 01 0304 finalise",
                                      timeout=15.0,
                                      pending_timeout=args.erase_timeout)
                check_finalize_response(profile, response)

        progress.stage_name("reset")
        print("\n== reset ==")
        ecu.req("1101", timeout=8.0, what="11 01 ECUReset")
    finally:
        try:
            ka.stop()
            if ka.sent:
                print(f"   keepalive: {ka.sent} TesterPresent frames"
                      + (f" ({ka.skipped} skipped while the socket was busy)"
                         if ka.skipped else ""))
            quiet.restore()
            if logf:
                logf.close()
        finally:
            progress.close()

    print("\n*** DONE ***")
    stats = progress.summary()
    if stats:
        print(stats)

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
    iface = _profile_iface(profile, args.iface)
    _check_iface(iface)

    logf = None
    if getattr(args, "logfile", None):
        os.makedirs(os.path.dirname(args.logfile) or ".", exist_ok=True)
        logf = open(args.logfile, "a")
        logf.write(f"\n==== {time.strftime('%F %T')} {profile.name} "
                   f"mem tx=0x{txid:03X} rx=0x{rxid:03X} ====\n")

    ecu = Ecu(iface, txid, rxid, execute=True, logfile=logf)
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

    quiet = BusQuiet(iface, FUNCTIONAL_ID, execute=True,
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
    settle_before_seed(getattr(args, "seed_delay", SEED_DELAY))
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
    dec = getattr(args, "decompress", False)
    download_blocks(ecu, sbl.wire_blocks(dec), "sbl", args.progress_interval,
                    dfi=sbl.wire_dfi(dec),
                    exit_crc=profile.transfer_exit_crc,
                    force=getattr(args, "force", False))
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
    erase_len = args.erase_len if args.erase_len is not None else length
    import hashlib
    print("=" * 72)
    print(f"MEMWRITE  {profile.name}  {args.infile} ({len(data)} bytes) "
          f"-> 0x{addr:08X}")
    print("=" * 72)
    print(f"   file sha256 {hashlib.sha256(data).hexdigest()}")
    print("   PLAN: load+run SBL, 31 01 FF00 erase "
          f"0x{erase_len:X}, 34 download 0x{length:X}, "
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
            print(f"\n== erase 0x{addr:08X} +0x{erase_len:X} ==")
            erase_region(ecu, addr, erase_len,
                         erase_timeout=args.erase_timeout)
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
def _split_flash_targets(args):
    """Split the positionals into VBF paths and bare ECU selectors.

    `--test-sbl` has nothing to flash, so there may be no VBF at all: the
    target is then named directly (`flash GWM --test-sbl`). A token is only
    read as a selector when it is not a file on disk, --test-sbl is in effect
    and the registry knows it — anything else stays a (missing) file, so a
    typo'd path still reports "not found" instead of "unknown ECU".
    """
    files, txids = [], []
    for t in args.vbf:
        if os.path.exists(t):
            files.append(t)
            continue
        profile = ecu_db.resolve(t) if args.test_sbl else None
        if profile is None:
            raise SystemExit(f"{t}: not found")
        if profile.txid not in txids:
            txids.append(profile.txid)
    if not files and not txids:
        raise SystemExit("flash requires VBF file(s), or an ECU name/id with "
                         "--test-sbl (e.g. `flash GWM --test-sbl`).")
    return files, txids


def do_flash(args):
    files, sel_txids = _split_flash_targets(args)
    # group by ecu_address
    groups = {t: [] for t in sel_txids}
    for f in files:
        v = Vbf(f)
        if v.ecu is None:
            raise SystemExit(f"{f}: VBF has no ecu_address; cannot target it.")
        groups.setdefault(v.ecu, []).append(f)
    if args.recovery:
        if len(groups) != 1:
            raise SystemExit("--recovery requires exactly one target ECU")
        if args.quiet_bus:
            raise SystemExit("--recovery cannot use --quiet-bus: it sends "
                             "functional traffic before the PBL is caught")
        if args.execute and not (args.hw or (args.sbl and args.secret is not None)):
            raise SystemExit("--recovery skips live F111 reads: pass --hw "
                             "<known F111>, or both --sbl PATH and --secret VALUE")
    elif len(groups) > 1:
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


def _profile_iface(profile, override):
    """Use an explicit --iface, otherwise the interface assigned to the ECU bus."""
    return override or profile.default_iface()


def _all_ifaces(override):
    """Interfaces needed for ALL: override once, or every registered bus."""
    if override:
        return [override]
    return sorted({p.default_iface() for p in ecu_db.ECUS.values()})


def _check_iface(iface):
    if not os.path.exists(f"/sys/class/net/{iface}"):
        raise SystemExit(f"interface {iface} does not exist.")
    if iface_is_up(iface) is False:
        raise SystemExit(f"interface {iface} is DOWN.")


def _check_ifaces(ifaces):
    for iface in ifaces:
        _check_iface(iface)


def _connect_by_selector(args):
    """Resolve --ecu (name or id) to a profile and open a live Ecu. Shared by
    ident / dtc / cleardtc / reset — none of these need a VBF."""
    profile = ecu_db.resolve(args.ecu)
    if profile is None:
        known = ", ".join(sorted({p.name.split()[0] for p in ecu_db.ECUS.values()}))
        raise SystemExit(f"unknown ECU {args.ecu!r}. Use a name ({known}), a "
                         f"CAN id (e.g. 726, 0x7E0), or ALL. See `list`.")
    rxid = args.rxid if args.rxid is not None else profile.resp_id()
    iface = _profile_iface(profile, args.iface)
    _check_iface(iface)
    ecu = Ecu(iface, profile.txid, rxid, execute=True)
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


def _session_and_unlock(args, profile, ecu):
    """Shared session + SecurityAccess preamble for readdid/writedid.

    Enters a diagnosticSession when --session is given, then performs a
    SecurityAccess seed/key exchange when unlocking. --sec-level/--secret/--hw
    imply --unlock so they are never a silent no-op. Secrets are keyed by the
    module's F111 hardware prefix (e.g. DV6T); with neither --hw nor --secret
    we read F111 live so an empty hw doesn't match nothing.
    """
    if getattr(args, "sec_level", None) is not None \
            or getattr(args, "secret", None) is not None \
            or getattr(args, "hw", None):
        args.unlock = True
    if getattr(args, "session", None) is not None:
        ecu.expect("10%02X" % args.session, 0x50,
                   "10 %02X diagnosticSession" % args.session, timeout=5.0)
        time.sleep(0.1)
        entered_session = True
    else:
        entered_session = False
    if not getattr(args, "unlock", False):
        return
    level = args.sec_level if args.sec_level is not None else 1
    if args.secret is not None:
        secret = (args.secret.to_bytes(5, "big")
                  if isinstance(args.secret, int) else args.secret)
    else:
        hw = args.hw or ""
        if not hw:
            fr = ecu.req("22F111", timeout=args.timeout, what="22 F111")
            if fr is not None and fr and fr[0] == 0x62 and len(fr) >= 3:
                hw = _ascii_sanitize(fr[3:]).strip()
                print(f"   F111: {hw!r}")
        secret = profile.pick_secret(hw, level)
        if secret is None:
            raise SystemExit(
                f"--unlock: no secret for {profile.name} F111 {hw!r} "
                f"level {level}; pass --secret 0x.... or --hw <F111>")
    # Settle only when we actually changed session: in the default session the
    # module is not entering a bootloader, so the wait would be pure cost.
    if entered_session:
        settle_before_seed(getattr(args, "seed_delay", SEED_DELAY))
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


def do_readdid(args):
    profile, ecu = _connect_by_selector(args)
    print(f"== {profile.name}  tx=0x{profile.txid:03X} rx=0x{ecu.rxid:03X} ==")
    ecu.wake(tries=getattr(args, "wake_tries", 8),
             timeout=getattr(args, "wake_timeout", 0.5))
    _session_and_unlock(args, profile, ecu)
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
    _session_and_unlock(args, profile, ecu)

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
    ifaces = _all_ifaces(args.iface)
    _check_ifaces(ifaces)
    # Keep the presence probe FAST — a full 8×0.5s wake per absent module would
    # make a 12-module scan crawl. Cap it; the user's --wake-* still cap it down.
    tries = min(getattr(args, "wake_tries", 2), 2)
    wtmo = min(getattr(args, "wake_timeout", 0.3), 0.3)
    print(f"== identity of ALL {len(ecu_db.ECUS)} registered modules "
          f"(interfaces {', '.join(ifaces)}) ==")
    present, absent = [], []
    for txid in sorted(ecu_db.ECUS):
        profile = ecu_db.ECUS[txid]
        iface = _profile_iface(profile, args.iface)
        rxid = profile.resp_id()
        ecu = Ecu(iface, txid, rxid, execute=True)
        # quick probe: is anything home? (bounded, so absent modules are fast)
        if ecu.wake(tries=tries, timeout=wtmo) is None \
                and ecu.read_did(profile.ident_dids[0], timeout=wtmo) is None:
            absent.append(profile)
            print(f"\n-- {profile.name}  tx=0x{txid:03X} rx=0x{rxid:03X}  "
                  f"iface={iface} -> no response, skipped")
            continue
        present.append(profile)
        print(f"\n-- {profile.name}  tx=0x{txid:03X} rx=0x{rxid:03X}  "
              f"iface={iface}")
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
    ifaces = _all_ifaces(args.iface)
    _check_ifaces(ifaces)
    tries = min(getattr(args, "wake_tries", 2), 2)
    wtmo = min(getattr(args, "wake_timeout", 0.3), 0.3)
    mask = args.status_mask
    print(f"== actual DTC counts across all {len(ecu_db.ECUS)} registered "
          f"modules (interfaces {', '.join(ifaces)}, status mask 0x{mask:02X}) ==\n")
    print("   %-39s %8s %8s" % ("module (tx/rx, iface)", "actual", "total"))
    print("   " + "-" * 57)
    rows, silent, grand = [], [], 0
    for txid in sorted(ecu_db.ECUS):
        profile = ecu_db.ECUS[txid]
        iface = _profile_iface(profile, args.iface)
        ecu = Ecu(iface, txid, profile.resp_id(), execute=True)
        label = (f"{profile.name.split()[0]} "
                 f"(0x{txid:03X}/0x{profile.resp_id():03X}, {iface})")
        # Fast presence probe first: absent modules cost only the short wake,
        # not a full DTC-read timeout. A present module then gets a generous
        # read window (its 19 02 can be a large multi-frame response).
        alive = ecu.wake(tries=tries, timeout=wtmo) is not None
        dtcs = None
        if alive:
            dtcs, _ = ecu.read_dtcs(status_mask=mask, timeout=20.0)
        if dtcs is None:
            silent.append(profile)
            print("   %-39s %8s %8s" % (label, "-", "-"))
            continue
        actual = sum(1 for _, s in dtcs if dtc_is_actual(s))
        grand += actual
        rows.append((profile, actual, len(dtcs)))
        flag = "  <--" if actual else ""
        print("   %-39s %8d %8d%s" % (label, actual, len(dtcs), flag))
    print("   " + "-" * 57)
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
    ifaces = _all_ifaces(args.iface)
    _check_ifaces(ifaces)
    print(f"== clear DTCs on ALL modules  (functional 0x{FUNCTIONAL_ID:03X}, "
          f"interfaces {', '.join(ifaces)}) ==")
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
    for iface in ifaces:
        functional_broadcast(iface, [payload], can_id=FUNCTIONAL_ID,
                             repeat=args.repeat)
        print(f"   {iface}: sent "
              f"{FUNCTIONAL_ID:03X}#{bytes([len(payload)] + payload).hex().upper()}"
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
    ifaces = _all_ifaces(args.iface)
    _check_ifaces(ifaces)
    mode = args.mode
    print(f"== ECUReset ALL modules  (functional 0x{FUNCTIONAL_ID:03X}, "
          f"interfaces {', '.join(ifaces)}, mode 0x{mode:02X}) ==")
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
    for iface in ifaces:
        functional_broadcast(iface, [payload], can_id=FUNCTIONAL_ID,
                             repeat=args.repeat)
        print(f"   {iface}: sent "
              f"{FUNCTIONAL_ID:03X}#{bytes([len(payload)] + payload).hex().upper()}"
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
    period = args.tp_interval if args.tp_interval > 0 else 2.0
    ecu = None
    quiets = []
    kas = []

    if _selector_is_all(args.ecu):
        # ALL spans both registered buses unless --iface explicitly collapses it
        # to one interface. Each bus needs its own functional arm + keepalive.
        ifaces = _all_ifaces(args.iface)
        _check_ifaces(ifaces)
        quiets = [BusQuiet(iface, FUNCTIONAL_ID, execute=True, enabled=True)
                  for iface in ifaces]
        kas = [Keepalive(_KaShim(iface), period=period, can_id=FUNCTIONAL_ID)
               for iface in ifaces]
        print(f"== silence ALL modules  (functional 0x{FUNCTIONAL_ID:03X}, "
              f"interfaces {', '.join(ifaces)}) ==")
        print("   NOTE: functional broadcast, responses suppressed — quiet is "
              "UNCONFIRMED. Watch with candump.")
        target = "ALL modules"
        restore_txt = (f"functional 0x{FUNCTIONAL_ID:03X} hardReset on "
                       f"{', '.join(ifaces)}")
    else:
        profile = ecu_db.resolve(args.ecu)
        if profile is None:
            raise SystemExit(f"unknown ECU {args.ecu!r}. Use a name, CAN id, "
                             "or ALL. See `list`.")
        iface = _profile_iface(profile, args.iface)
        _check_iface(iface)
        rxid = args.rxid if args.rxid is not None else profile.resp_id()
        ecu = Ecu(iface, profile.txid, rxid, execute=True)
        print(f"== silence {profile.name}  tx=0x{profile.txid:03X} "
              f"rx=0x{ecu.rxid:03X}  iface {iface} ==")
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
        kas = [Keepalive(ecu, period=period, can_id=None)]  # physical keepalive
        target = profile.name
        restore_txt = "11 01 ECUReset"

    if args.duration:
        print(f"   holding {target} silent for {args.duration:.0f}s "
              f"(TesterPresent every {period:.1f}s)...")
    else:
        print(f"   holding {target} silent (TesterPresent every {period:.1f}s)."
              "  Press Ctrl-C to stop and restore.")

    try:
        for quiet in quiets:
            quiet.arm()
        for ka in kas:
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
        for ka in kas:
            ka.stop()
        sent = sum(ka.sent for ka in kas)
        if sent:
            print(f"   keepalive: {sent} TesterPresent frames sent")
        print(f"   restoring ({restore_txt})...")
        for quiet in quiets:
            quiet.restore()
        if ecu is not None:
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
        print(f"         {p.bus} -> {p.default_iface()}  rx 0x{p.resp_id():03X}  "
              f"secrets:{len(p.secrets)}  finalise:{p.finalize}")
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
                    parts = (a.metavar or "").split("|")
                    if "ECU" in parts:
                        takes_ecu = True
                    if "FILE" in parts:
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
    # IPC DM5T-14F094 (C-MAX Energi hybrid): level-3 secret solved from the
    # UCDS 2E writedid captures in IPC/c-max_el/hybrid/. Three independent
    # seed/key pairs from the same module must all reproduce, which is what
    # distinguishes a solved secret from one that fits a single session.
    # IPC DM5T-14F094 (C-MAX Energi hybrid): the stored level-3 secret, read
    # out of live RAM at 0x400086D3 with 23 ReadMemoryByAddress and confirmed
    # on the module. The three UCDS captures in IPC/c-max_el/hybrid/ pin only
    # the keygen CLASS (2^16 secrets share every key), so the solver's
    # representative 000024E4DE is equally valid -- assert BOTH reproduce the
    # captured pairs, and that they are genuinely interchangeable.
    _ipc = ecu_db.get_profile(0x720)
    assert _ipc is not None
    _ipc_dm5t = _ipc.pick_secret("DM5T-14F094-AB", 3)
    chk("IPC DM5T level3 secret registered",
        _ipc_dm5t == bytes.fromhex("0102030405"), (_ipc_dm5t or b"").hex())
    chk("the solver's class representative is keygen-equivalent",
        all(ford_seckey.key_from_seed(bytes([a, b, c]), _ipc_dm5t or b"\0" * 5)
            == ford_seckey.key_from_seed(bytes([a, b, c]),
                                        bytes.fromhex("000024E4DE"))
            for a, b, c in ((0, 0, 1), (0x36, 0xCB, 0x31), (0xFF, 0xFF, 0xFF),
                            (0x12, 0x34, 0x56))))
    for _seed, _key in (("36CB31", "a6d25e"), ("C721E8", "ce1fc2"),
                        ("C5D162", "6a9802")):
        _got = ford_seckey.key_from_seed(bytes.fromhex(_seed),
                                        _ipc_dm5t or b"\0" * 5).hex()
        chk(f"IPC DM5T level3 reproduces {_seed} -> {_key.upper()}",
            _got == _key, _got)
    # The generic IPC rules must not be shadowed by (or shadow) the new one.
    chk("IPC generic level3 secret unchanged for other hardware",
        _ipc.pick_secret("CM5T-14F094-AA", 3) == bytes.fromhex("8408F57701"))
    chk("IPC EJ7T level1 secret unchanged",
        _ipc.pick_secret("EJ7T-14F094-BB", 1) == bytes.fromhex("00004A7722"))
    # The DM5T PBL level-1 secret unlocked the live module; it is distinct
    # from the level-3 secret extracted from RAM.
    chk("IPC DM5T level1 PBL secret registered",
        _ipc.pick_secret("DM5T-14F094-AB", 1) == bytes.fromhex("EC6D038211"))
    chk("IPC finalises and requires the boot-commit success status",
        _ipc.finalize and _ipc.finalize_response == bytes.fromhex("710103041002"))
    check_finalize_response(_ipc, bytes.fromhex("710103041002"))
    try:
        check_finalize_response(_ipc, bytes.fromhex("710103041001"))
    except SystemExit:
        chk("IPC rejects a positive SID with an unsuccessful boot status", True)
    else:
        chk("IPC rejects a positive SID with an unsuccessful boot status", False)
    # GROUND TRUTH candump-stock-flash.log: 706#1008310103010082 + 21 00 00
    # reassembles to 31 01 0301 00 82 00 00 -> FULL 4-byte call address, NOT
    # the high-half (a FirstFrame-only misread earned NRC 22 at SBL-start).
    chk("IPMA uses FULL 4-byte SBL call address", not ipma.sbl_call_halfword)
    chk("IPMA default SBL", ipma.pick_sbl("x") == "CV4T-14F399-AF.VBF")
    # GWM: secret derived from the UCDS writedid captures
    # (ford/GWM/ucds_gwm_writedid{,2,3}.log) — 10 03, then 27 03 seed E68E01
    # answered with 27 04 key EECCA0. Reproduce that exact pair.
    gwm = ecu_db.get_profile(0x716)
    _gwm_l3 = gwm.pick_secret("", 3)
    _gwm_l1 = gwm.pick_secret("", 1)
    chk("GWM level3 secret registered",
        _gwm_l3 == bytes.fromhex("00000D14EF"), (_gwm_l3 or b"").hex())
    chk("GWM level3 secret reproduces writedid key E68E01 -> EECCA0",
        _gwm_l3 is not None
        and ford_seckey.key_from_seed([0xE6, 0x8E, 0x01],
                                      _gwm_l3).hex() == "eecca0",
        ford_seckey.key_from_seed([0xE6, 0x8E, 0x01],
                                  _gwm_l3 or b"\0" * 5).hex())
    # ucds_gwm_flash.log: the FLASH uses level 1 (10 02 -> 27 01/02).
    chk("GWM level1 secret registered",
        _gwm_l1 == bytes.fromhex("0000F64E88"), (_gwm_l1 or b"").hex())
    chk("GWM level1 secret reproduces flash key 790F2C -> 7BBE1D",
        _gwm_l1 is not None
        and ford_seckey.key_from_seed([0x79, 0x0F, 0x2C],
                                      _gwm_l1).hex() == "7bbe1d",
        ford_seckey.key_from_seed([0x79, 0x0F, 0x2C],
                                  _gwm_l1 or b"\0" * 5).hex())
    chk("GWM level1 and level3 secrets are distinct", _gwm_l1 != _gwm_l3)
    chk("GWM SBL == CM5T-14F532-AA.vbf",
        gwm.pick_sbl("") == "CM5T-14F532-AA.vbf", str(gwm.pick_sbl("")))
    chk("GWM finalises (31 01 0304 seen in capture)", gwm.finalize)
    chk("GWM SIGCFG part type is report-only (not the EXE gate)",
        gwm.ident_did_by_type.get("SIGCFG") not in (None, "F188"),
        str(gwm.ident_did_by_type.get("SIGCFG")))
    # Flash-order guard. GROUND TRUTH ford/GWM/ucds_gwm_flash.log: the EXE part
    # erases 0x8000+0x38000, which COVERS the SIGCFG load address 0x8000 — so
    # EXE must go first. Assert the guard accepts UCDS's order and rejects the
    # reverse one, which would silently erase the just-written config.
    _gdir = "/home/gl/Projects/ford/GWM"
    _exe = os.path.join(_gdir, "EG9T-14F530-DA.VBF")
    _sig = os.path.join(_gdir, "EG9T-14F529-DA.VBF")
    if os.path.exists(_exe) and os.path.exists(_sig):
        ve, vs = Vbf(_exe), Vbf(_sig)
        try:
            _check_flash_order([ve, vs])
            _ok_order = True
        except SystemExit:
            _ok_order = False
        chk("flash order EXE-then-SIGCFG accepted (UCDS order)", _ok_order)
        try:
            _check_flash_order([vs, ve])
            _bad_order = False
        except SystemExit:
            _bad_order = True
        chk("flash order SIGCFG-then-EXE REFUSED (erase would wipe it)",
            _bad_order)
        try:
            _check_flash_order([vs, ve], force=True)
            _forced = True
        except SystemExit:
            _forced = False
        chk("flash order --force downgrades the refusal to a warning", _forced)
    else:
        print("  SKIP  GWM VBFs not present for the flash-order guard")

    # Jade/QNX IPC parts address a VIRTUAL map (virtual_start_address
    # 0x30000000 + a 4-byte lookup-index cell at 0x3FFFFFFC), not flash. Both
    # addresses repeat many times within ONE file, so the linear-interval
    # bookkeeping reports every ordering of two such parts as fatal. Assert the
    # exemption fires on a real Jade file and that plain linear parts are still
    # checked.
    _ldir = "/home/gl/Projects/ford/IPC/Lincoln"
    _jade = [os.path.join(_ldir, n) for n in
             ("EJ7T-14C088-AH.vbf", "EJ7T-14C088-BH.vbf",
              "EJ7T-14C026-BH.vbf")]
    if all(os.path.exists(p) for p in _jade):
        _jv = [Vbf(p) for p in _jade]
        for _v in _jv:
            chk(f"{os.path.basename(_v.path)} detected as a virtual map",
                _is_virtual_map(_v))
        try:
            _check_flash_order(_jv)
            _jade_ok = True
        except SystemExit:
            _jade_ok = False
        chk("Jade IPC parts accepted in any order (guard does not apply)",
            _jade_ok)
    else:
        print("  SKIP  Lincoln IPC VBFs not present for the virtual-map guard")
    if os.path.exists(_exe):
        chk("a linear part is NOT mistaken for a virtual map",
            not _is_virtual_map(Vbf(_exe)))

    print("\n== per-ECU CAN interface selection ==")
    chk("BCM is HS-CAN and defaults to can0",
        getattr(bcm, "bus", None) == "HS-CAN"
        and getattr(bcm, "default_iface", lambda: None)() == "can0")
    chk("IPC is MS-CAN and defaults to can1",
        getattr(ecu_db.get_profile(0x720), "bus", None) == "MS-CAN"
        and getattr(ecu_db.get_profile(0x720), "default_iface", lambda: None)()
        == "can1")
    chk("PSCM is HS-CAN and defaults to can0",
        getattr(pscm, "bus", None) == "HS-CAN"
        and getattr(pscm, "default_iface", lambda: None)() == "can0")
    chk("PCM is HS-CAN and defaults to can0",
        getattr(ecu_db.get_profile(0x7E0), "bus", None) == "HS-CAN"
        and getattr(ecu_db.get_profile(0x7E0), "default_iface", lambda: None)()
        == "can0")
    _expected_ms = {0x720, 0x727, 0x733, 0x7A5}
    _actual_ms = {txid for txid, p in ecu_db.ECUS.items() if p.bus == "MS-CAN"}
    chk("all registered MS-CAN modules default to can1",
        _actual_ms == _expected_ms
        and all(ecu_db.ECUS[x].default_iface() == "can1" for x in _actual_ms),
        f"actual={sorted(hex(x) for x in _actual_ms)}")
    chk("all other registered modules are HS-CAN on can0",
        all(p.bus == "HS-CAN" and p.default_iface() == "can0"
            for txid, p in ecu_db.ECUS.items() if txid not in _expected_ms))
    _iface_for = globals().get("_profile_iface")
    chk("interface resolver exists", callable(_iface_for))
    if callable(_iface_for):
        chk("interface resolver uses profile default",
            _iface_for(bcm, None) == "can0")
        chk("--iface overrides profile default",
            _iface_for(bcm, "vcan7") == "vcan7")
    _all_iface_fn = globals().get("_all_ifaces")
    chk("ALL interface resolver exists", callable(_all_iface_fn))
    if callable(_all_iface_fn):
        chk("ALL defaults cover HS can0 and MS can1",
            _all_iface_fn(None) == ["can0", "can1"],
            str(_all_iface_fn(None)))
        chk("ALL --iface override uses only override",
            _all_iface_fn("vcan7") == ["vcan7"])
    _bp = build_parser()
    chk("diagnostic --iface default is automatic",
        _bp.parse_args(["ident", "BCM"]).iface is None)
    chk("flash --iface default is automatic",
        _bp.parse_args(["flash", "x.vbf"]).iface is None)
    chk("explicit --iface is preserved",
        _bp.parse_args(["ident", "BCM", "--iface", "vcan7"]).iface == "vcan7")
    chk("single-ECU connection resolves the profile interface",
        "_profile_iface" in inspect.getsource(_connect_by_selector))
    chk("flash session resolves the profile interface",
        "_profile_iface" in inspect.getsource(flash_session))
    chk("memory/SBL session resolves the profile interface",
        "_profile_iface" in inspect.getsource(_open_sbl_session))
    chk("ALL operations resolve both registered interfaces",
        all("_all_ifaces" in inspect.getsource(fn)
            for fn in (_ident_all, _dtc_all, _cleardtc_all, _reset_all,
                       do_silence)))

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
    # req() is a thin locking wrapper around _req(); inspect BOTH so these
    # source assertions keep covering the real recv loop.
    src = inspect.getsource(_vbf.Ecu.req) + inspect.getsource(_vbf.Ecu._req)
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

    # NRC 0x21 busyRepeatRequest must be retried a BOUNDED number of times and
    # then RETURNED. GROUND TRUTH: a dead/bootloader IPC answered `22 F124`
    # with `7F 22 21` forever; the old unbounded retry loop resent the request
    # in a tight loop and the flasher never reached the plan (candump showed a
    # 720/728 storm). Assert both halves: it does retry, and it gives up.
    class _BusySock:
        def __init__(self):
            self.sends = 0

        def settimeout(self, t):
            pass

        def send(self, d):
            self.sends += 1

        def recv(self, n):
            return bytes([0x7F, 0x22, 0x21])          # busyRepeatRequest

    eb = _vbf.Ecu("can0", 0x720, 0x728, execute=False)
    eb.execute = True
    eb.s = _BusySock()
    t0 = time.monotonic()
    rb = eb.req("22F124", timeout=1.0, busy_retries=3)
    dt = time.monotonic() - t0
    chk("busyRepeatRequest is RETRIED (not returned immediately)",
        eb.s.sends == 4, f"{eb.s.sends} sends for 3 retries")
    chk("busyRepeatRequest retry is BOUNDED (returns the negative)",
        rb is not None and rb[0] == 0x7F and rb[2] == 0x21, _vbf.fmt(rb))
    chk("bounded busy retry terminates quickly", dt < 5.0, f"{dt:.2f}s")
    chk("req() does not loop forever on 0x21 (source has a busy bound)",
        "busy > busy_retries" in src)

    # An ident read must report WHY it is blank: a refusing module is ALIVE.
    eb2 = _vbf.Ecu("can0", 0x720, 0x728, execute=False)
    eb2.execute = True
    eb2.s = _BusySock()
    chk("read_did returns None on a negative response",
        eb2.read_did("F111") is None)
    chk("read_did records the NRC so the caller can say 'alive but refusing'",
        (eb2.last_did_status or "").startswith("refused: NRC 21"),
        str(eb2.last_did_status))

    class _SilentSock:
        def settimeout(self, t):
            pass

        def send(self, d):
            pass

        def recv(self, n):
            raise socket.timeout()

    es = _vbf.Ecu("can0", 0x720, 0x728, execute=False)
    es.execute = True
    es.s = _SilentSock()
    es.read_did("F111")
    chk("a genuinely silent ECU is reported differently from a refusing one",
        es.last_did_status == "no response", str(es.last_did_status))

    # KEEPALIVE / ISO-TP SOCKET RACE. GROUND TRUTH (bench IPC, candump
    # 2026-09-29): a PHYSICAL TesterPresent keepalive shares the target's
    # ISO-TP socket. 43 of 48 `3E 80` frames were written between a FirstFrame
    # and its ConsecutiveFrames during 36 TransferData; the kernel aborted the
    # segmented send and the next recv() raised
    # OSError [Errno 70] Communication error on send, 36.9% into a 2.4 MiB
    # block. Assert the transaction lock serialises the two writers.
    chk("Ecu owns a lock for whole transactions", hasattr(_vbf.Ecu, "req")
        and "self.lock" in inspect.getsource(_vbf.Ecu.req))
    chk("Keepalive takes the ECU lock non-blockingly (physical mode)",
        "self.ecu.lock.acquire(blocking=False)"
        in inspect.getsource(_vbf.Keepalive.start))

    class _SegSock:
        """Fails if a write lands inside a multi-frame send, as the kernel does.

        The race window is INSIDE send(): the kernel streams a FirstFrame plus
        N ConsecutiveFrames and only then returns. A concurrent write during
        that window is what corrupts the transfer. An earlier version of this
        fake flipped the flag only BETWEEN send() and recv(), leaving a window
        so small the keepalive never hit it — it passed with the fix reverted.
        """
        def __init__(self):
            self.in_segment = False
            self.violations = 0
            self.frames = 0

        def settimeout(self, t):
            pass

        def send(self, d):
            self.frames += 1
            if self.in_segment:
                self.violations += 1
                raise OSError(70, "Communication error on send")
            if len(d) > 7:                      # segmented on the wire
                self.in_segment = True
                try:
                    # ~3 ms for a 130-byte transfer at 500 kbit/s. Time must
                    # actually pass here or there is no window to race.
                    time.sleep(0.002)
                finally:
                    self.in_segment = False

        def recv(self, n):
            return bytes([0x76, 0x01])

    seg = _SegSock()
    eseg = _vbf.Ecu("can0", 0x720, 0x728, execute=False)
    eseg.execute = True
    eseg.s = seg
    # Drive the REAL Keepalive class, not a hand-rolled imitation: a local
    # copy of the locking logic would pass even with the fix reverted out of
    # vbf.py (verified — it did), testing the test instead of the code.
    kseg = _vbf.Keepalive(eseg, period=0.001)
    kseg.start()
    try:
        for _ in range(200):
            eseg.req("36" + "01" + "AA" * 128, timeout=1.0)
    finally:
        kseg.stop()
    chk("no keepalive write lands inside a segmented transfer (Errno 70 race)",
        seg.violations == 0, f"{seg.violations} interleavings")
    chk("the keepalive really did contend for the socket",
        kseg.sent + kseg.skipped > 0,
        f"sent={kseg.sent} skipped={kseg.skipped}")

    # IDENTITY GATE resolves the DID from the PART FAMILY, not sw_part_type.
    # GROUND TRUTH (bench Lincoln IPC, 2026-09-29): the cluster carries FOUR
    # software parts across four DIDs —
    #   F188=EJ7T-14C026-AK  F120=EJ7T-14C026-BH
    #   F124=EJ7T-14C088-AH  F125=EJ7T-14C088-BH
    # while each VBF only declares EXE or DATA. The old static EXE->F188 map
    # compared EJ7T-14C088-AH (an EXE) against the 14C026 DID and refused a
    # legitimate flash; --force then hid a real gate rather than an error.
    print("\n== identity gate: part-family DID resolution ==")
    _bench = {"F188": "EJ7T-14C026-AK", "F120": "EJ7T-14C026-BH",
              "F124": "EJ7T-14C088-AH", "F125": "EJ7T-14C088-BH",
              "F111": "EJ7T-14F094-AA", "F113": "EJ7T-10849-AK"}
    chk("part_family('EJ7T-14C088-AH') == '14C088'",
        part_family("EJ7T-14C088-AH") == "14C088",
        str(part_family("EJ7T-14C088-AH")))
    chk("part_family ignores a non-part string",
        part_family("EJAK074768") is None)
    _ipc = ecu_db.get_profile(0x720)
    _lin = "/home/gl/Projects/ford/IPC/Lincoln"
    _cases = [("EJ7T-14C088-AH.vbf", "F124", "exact"),
              ("EJ7T-14C088-BH.vbf", "F125", "exact"),
              ("EJ7T-14C026-AK.vbf", "F188", "exact"),
              ("EJ7T-14C026-BH.vbf", "F120", "exact")]
    if all(os.path.exists(os.path.join(_lin, n)) for n, _, _ in _cases):
        for fn, want_did, want_verdict in _cases:
            vv = Vbf(os.path.join(_lin, fn))
            d, live, verdict = resolve_gate_did(vv, _bench, _ipc)
            chk(f"{fn} [{vv.ptype}] gates on {want_did} ({want_verdict})",
                d == want_did and verdict == want_verdict,
                f"got {d} / {verdict}")
        # A revision change in the same slot is a NORMAL flash, not a refusal.
        vv = Vbf(os.path.join(_lin, "EJ7T-14C088-AH.vbf"))
        d, live, verdict = resolve_gate_did(
            vv, dict(_bench, F124="EJ7T-14C088-AG"), _ipc)
        chk("a same-family revision change is allowed ('family')",
            d == "F124" and verdict == "family", f"{d} / {verdict}")
        # A part whose family appears on NO DID is the real error case.
        d, live, verdict = resolve_gate_did(
            vv, {"F188": "CV6T-14C217-AR"}, _ipc)
        chk("a foreign part family is REFUSED ('nomatch')",
            verdict == "nomatch", f"{d} / {verdict}")
        # A hardware DID must never satisfy the gate.
        d, live, verdict = resolve_gate_did(vv, {"F111": "EJ7T-14C088-AH"},
                                            _ipc)
        chk("F111 (hardware) is not usable as a software gate",
            verdict != "exact", f"{d} / {verdict}")
    else:
        print("  SKIP  Lincoln IPC VBFs not present for the gate test")

    # DECOMPRESS OPTION: by default a dfi-0x10 container goes on the wire
    # verbatim (34 10 <addr> <compressed-len>); --decompress expands it on the
    # host and must then declare dfi 0x00 with the UNPACKED length.
    print("\n== --decompress: plain transmission of an LZSS payload ==")
    import binascii as _ba
    _lz = "/home/gl/Projects/ford/IPC/GJ5T-14C026-DL.vbf"
    if os.path.exists(_lz):
        vz = Vbf(_lz)
        chk("the test file is LZSS-compressed (dfi 0x10)", vz.compressed(),
            f"dfi={vz.dfi}")
        chk("default wire dfi is the header's 0x10", vz.wire_dfi() == 0x10,
            f"0x{vz.wire_dfi():02X}")
        chk("--decompress declares dfi 0x00",
            vz.wire_dfi(True) == 0x00, f"0x{vz.wire_dfi(True):02X}")
        pk = vz.flash_blocks()
        pl = vz.flash_blocks(decompress=True)
        chk("same block count either way", len(pk) == len(pl),
            f"{len(pk)} vs {len(pl)}")
        chk("unpacked blocks are larger than the stored ones",
            sum(b["length"] for b in pl) > sum(b["length"] for b in pk),
            f"{sum(b['length'] for b in pl)} vs "
            f"{sum(b['length'] for b in pk)}")
        chk("unpacked length == len(data) (what 34 declares)",
            all(b["length"] == len(b["data"]) for b in pl))
        chk("stored_length keeps the on-disk length",
            all(b["stored_length"] == o["length"] for b, o in zip(pl, pk)))
        chk("load addresses are unchanged by --decompress",
            [b["start"] for b in pl] == [b["start"] for b in pk])
        chk("the expanded bytes are the ones the block CRC-16 covers",
            all(_ba.crc_hqx(b["data"], 0xFFFF) == b["crc"] for b in pl))
        # A raw container must be byte-identical with and without the flag.
        _raw = next((p for p in (os.path.join(SBL_DIR, n)
                                 for n in sorted(os.listdir(SBL_DIR)))
                     if p.lower().endswith(".vbf") and not Vbf(p).compressed()),
                    None)
        if _raw:
            vr = Vbf(_raw)
            chk("--decompress is a no-op for a raw container",
                vr.wire_dfi(True) == vr.wire_dfi()
                and vr.flash_blocks(decompress=True) == vr.flash_blocks(),
                os.path.basename(_raw))
    else:
        print(f"  SKIP  {os.path.basename(_lz)} not present")

    # LZSS DECODER: the fast path must be byte-identical to the literal
    # Okumura reference decoder. lzss_decode() drops the materialised ring in
    # favour of back-copies into the output, which is only valid because a ring
    # cell IS the output byte 1..1024 back — assert it instead of trusting it,
    # on real blocks and on crafted streams that exercise the virgin ring.
    print("\n== LZSS decoder: fast path == reference ==")
    import random as _rnd

    def _enc(bits):
        o = bytearray()
        a = n = 0
        for b in bits:
            a = (a << 1) | b
            n += 1
            if n == 8:
                o.append(a)
                a = n = 0
        if n:
            o.append(a << (8 - n))
        return bytes(o)

    def _lit(ch):
        return [1] + [(ch >> k) & 1 for k in range(7, -1, -1)]

    def _mat(i, j):
        return ([0] + [(i >> k) & 1 for k in range(9, -1, -1)]
                + [(j >> k) & 1 for k in range(3, -1, -1)])

    # a match as the very first token reads the 0x20-filled virgin ring
    _virgin = _enc(_mat(1, 3))
    chk("a match into the virgin ring yields 0x20 spaces",
        _vbf.lzss_decode(_virgin) == _vbf._lzss_decode_ref(_virgin) == b"     ",
        repr(_vbf.lzss_decode(_virgin)))
    _rnd.seed(7)
    _bad = 0
    for _ in range(600):
        _bits = []
        for _ in range(_rnd.randint(1, 40)):
            if _rnd.random() < 0.5:
                _bits += _lit(_rnd.randrange(256))
            else:
                _bits += _mat(_rnd.randrange(1, 1024), _rnd.randrange(16))
        _d = _enc(_bits)
        if _vbf.lzss_decode(_d) != _vbf._lzss_decode_ref(_d):
            _bad += 1
    chk("600 randomised streams decode identically", _bad == 0,
        f"{_bad} mismatches")

    # The ENCODER must round-trip through both decoders — it is the thing a
    # module will be asked to unpack, so a bad token here is a brick.
    _ebad = []
    _ecases = [b"", b"A", b"AB", b"\xFF" * 5000, bytes(range(256)) * 8,
               b"ABCABCABC" * 200, b"\x00" * 4096 + b"\xAA" * 9,
               b"\xFF" * 1023 + b"\x01",      # ring pos 1023 unaddressable
               b"\xFF" * 1024 + b"\x01",
               b"\xFF" * 1025 + b"\x01"]
    _rnd.seed(11)
    for _ in range(150):
        _n = _rnd.randint(1, 3000)
        _ecases.append(bytes(_rnd.randrange(_rnd.choice([2, 4, 256]))
                             for _ in range(_n)))
    for _d in _ecases:
        _packed = _vbf.lzss_encode(_d)
        if _vbf.lzss_decode(_packed) != _d \
                or _vbf._lzss_decode_ref(_packed) != _d:
            _ebad.append(len(_d))
    chk(f"lzss_encode round-trips {len(_ecases)} payloads through BOTH decoders",
        not _ebad, f"failed at lengths {_ebad[:5]}")
    _ff = _vbf.lzss_encode(b"\xFF" * 5000)
    chk("an all-0xFF payload compresses hard (match coding works)",
        len(_ff) < 5000 // 8, f"{len(_ff)} B for 5000")
    if os.path.exists(_lz):
        # reuse the Vbf from the --decompress section: its LZSS result is
        # memoised, so this costs no second 16 MiB decode
        _blk = vz.blocks[0]
        # the reference is slow, so prove equivalence on a prefix of a REAL
        # block (the full-corpus comparison is a separate manual run)
        _pre = _blk["data"][:200000]
        chk("a real compressed block decodes identically to the reference",
            _vbf.lzss_decode(_pre) == _vbf._lzss_decode_ref(_pre))
        _t0 = time.time()
        _full = _vbf.lzss_decode(_blk["data"])
        _dt = time.time() - _t0
        chk("the full real block still matches its stored CRC-16",
            _ba.crc_hqx(_full, 0xFFFF) == _blk["crc"])
        print(f"        {len(_blk['data']) / 1048576:.1f} MiB -> "
              f"{len(_full) / 1048576:.1f} MiB in {_dt:.2f}s "
              f"({len(_full) / _dt / 1048576:.0f} MiB/s)")

    # BLANK-SKIP: a long 0xFF run inside an ERASED region need not be
    # transmitted. The acceptance test is reassembly: fragments laid over a
    # 0xFF canvas must reproduce the full payload byte-for-byte.
    print("\n== --skip-blank: omit erased-blank padding ==")
    _bb = ("/home/gl/Projects/ford/IPC/c-max_el/hybrid/"
           "HM5T-14C088-BB.VBF")
    if os.path.exists(_bb):
        vb = Vbf(_bb)
        full = vb.flash_blocks(decompress=True)
        part = vb.flash_blocks(decompress=True, skip_blank=0x1000)
        fl = sum(b["length"] for b in full)
        pl = sum(b["length"] for b in part)
        chk("the split produces more, smaller fragments",
            len(part) > len(full) and pl < fl,
            f"{len(full)}->{len(part)} blocks, {fl}->{pl} B")
        chk("LOSSLESS: fragments reassemble to the full payload",
            vb.verify_blank_skip(decompress=True, skip_blank=0x1000) == [],
            str(vb.verify_blank_skip(decompress=True, skip_blank=0x1000)))
        chk("every fragment length == len(its data)",
            all(b["length"] == len(b["data"]) for b in part))
        chk("every fragment is non-empty",
            all(b["length"] > 0 for b in part))
        chk("fragments stay inside the parent block's address range",
            all(full[0]["start"] <= b["start"]
                and b["start"] + b["length"] <= full[0]["start"] + fl
                for b in part))
        chk("fragments are ordered and non-overlapping",
            all(part[i]["start"] + part[i]["length"] <= part[i + 1]["start"]
                for i in range(len(part) - 1)))
        chk("every fragment start is 0x100-aligned (write granularity)",
            all(b["start"] % 0x100 == 0 for b in part[1:]),
            str([hex(b["start"]) for b in part]))
        chk("every skipped gap lies inside an erase region",
            all(vb._erase_covers(part[i]["start"] + part[i]["length"],
                                 part[i + 1]["start"]
                                 - (part[i]["start"] + part[i]["length"]))
                for i in range(len(part) - 1)))
        chk("no NON-0xFF byte is ever dropped",
            all(b == 0xFF for i in range(len(part) - 1)
                for b in vb.flash_blocks(decompress=True)[0]["data"][
                    part[i]["start"] + part[i]["length"] - full[0]["start"]:
                    part[i + 1]["start"] - full[0]["start"]]))
        sent, fullb, nf, np_ = vb.blank_skip_report(decompress=True,
                                                    skip_blank=0x1000)
        chk("report agrees with the block lists",
            (sent, fullb, nf, np_) == (pl, fl, len(part), len(full)))
        print(f"        saving: {fl / 1048576:.1f} -> {pl / 1048576:.1f} MiB "
              f"({100.0 * (fl - pl) / fl:.0f}% less) in {len(part)} fragments")
        # The library still refuses a bare split on compressed data: without
        # decompress OR recompress an offset inside LZSS data is not an address.
        try:
            vb.flash_blocks(skip_blank=0x1000)
            chk("skip_blank refused on compressed data without "
                "decompress/recompress", False, "no exception")
        except ValueError as e:
            chk("skip_blank refused on compressed data without "
                "decompress/recompress", "recompress=True" in str(e))
        # A compressed container is now blank-skipped by expand -> split ->
        # RE-PACK, so it still goes on the wire as dfi 0x10. The plain
        # (--decompress) route stays available as the explicit opt-out.
        _rc = vb.flash_blocks(skip_blank=0x1000, recompress=True)
        _on_disk = sum(b["length"] for b in vb.flash_blocks())
        _wire = sum(b["length"] for b in _rc)
        chk("recompress keeps the fragment count of the plain split",
            len(_rc) == len(part), f"{len(_rc)} vs {len(part)}")
        chk("every re-packed fragment carries plain_length",
            all("plain_length" in b for b in _rc))
        chk("re-packed fragments decode back to the kept plaintext",
            all(_vbf.lzss_decode(r["data"]) == p["data"]
                for r, p in zip(_rc, part)))
        chk("the re-packed wire size is SMALLER than sending the file as-is",
            _wire < _on_disk,
            f"{_wire / 1048576:.2f} vs {_on_disk / 1048576:.2f} MiB")
        _rcp = vb.verify_blank_skip(skip_blank=0x1000, recompress=True)
        chk("LOSSLESS with recompress (decode + reassemble)", _rcp == [],
            str(_rcp))
        print(f"        compressed route: {_on_disk / 1048576:.2f} MiB as-is "
              f"-> {_wire / 1048576:.2f} MiB re-packed "
              f"({100.0 * (_on_disk - _wire) / _on_disk:.0f}% less), "
              f"{sum(b['plain_length'] for b in _rc) / 1048576:.1f} MiB written")
        # skip_blank=0 must be bit-identical to not passing it at all.
        chk("skip_blank=0 is a no-op",
            vb.flash_blocks(decompress=True, skip_blank=0) == full)
    else:
        print(f"  SKIP  {os.path.basename(_bb)} not present")

    # The erase-coverage rule is the whole safety argument, so prove it is
    # load-bearing on a synthetic part rather than hoping a corpus file
    # exercises it: a blank run OUTSIDE the erase map must be transmitted,
    # because there the pre-existing flash content is unknown.
    def _synth(erase):
        sv = Vbf.__new__(Vbf)
        sv.path, sv.dfi, sv.omit, sv._unpacked = "<synthetic>", None, [], {}
        d = (b"\xAA" * 0x100 + b"\xFF" * 0x2000 + b"\xBB" * 0x100
             + b"\xFF" * 0x2000 + b"\xCC" * 0x100)
        sv.blocks = [dict(start=0x1000, length=len(d), crc=0, data=d)]
        sv.erase = erase
        return sv
    _s1 = _synth([(0x1000, 0x2200)])      # covers the 1st blank run only
    chk("a blank run OUTSIDE the erase map is NOT skipped",
        len(_s1.flash_blocks(skip_blank=0x1000)) == 2,
        f"{len(_s1.flash_blocks(skip_blank=0x1000))} fragments")
    _s2 = _synth([(0x1000, 0x5000)])      # covers both runs
    chk("both blank runs are skipped when both are erased",
        len(_s2.flash_blocks(skip_blank=0x1000)) == 3,
        f"{len(_s2.flash_blocks(skip_blank=0x1000))} fragments")
    chk("with NO erase map nothing is skipped",
        len(_synth([]).flash_blocks(skip_blank=0x1000)) == 1)
    chk("the synthetic splits are lossless too",
        _s1.verify_blank_skip(skip_blank=0x1000) == []
        and _s2.verify_blank_skip(skip_blank=0x1000) == [])
    # An omit region is NOT erased, so a blank run in it must be transmitted.
    # Layout: two blocks, one of which sits in the omitted (protected) erase
    # region — that block is not downloaded at all, and the remaining block's
    # blank run is only skippable via the NON-omitted erase region.
    _s4 = _synth([(0x1000, 0x2200), (0x8000, 0x2200)])
    _s4.omit = [(0x8000, 0x2200)]
    _d = (b"\xAA" * 0x100 + b"\xFF" * 0x2000 + b"\xBB" * 0x100)
    _s4.blocks = [dict(start=0x1000, length=len(_d), crc=0, data=_d),
                  dict(start=0x8000, length=len(_d), crc=0, data=_d)]
    _f4 = _s4.flash_blocks(skip_blank=0x1000)
    chk("the OMIT-protected block is not downloaded at all",
        all(b["start"] < 0x8000 for b in _f4),
        str([hex(b["start"]) for b in _f4]))
    chk("_erase_covers ignores an omitted erase region",
        _s4._erase_covers(0x1100, 0x2000)
        and not _s4._erase_covers(0x8100, 0x2000))

    # STALE-FRAME DRAIN: a frame that is neither the positive nor the negative
    # response to THIS request (e.g. a duplicated 50 02 programmingSession
    # still queued when we send 27 01) must be discarded, not returned.
    chk("req() drains stale frames (skips non-matching SID)",
        "stale" in src.lower())

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

    # INTEGRITY GATE: a CRC mismatch aborts, --force downgrades it to a
    # warning (a deliberately patched file whose CRCs were not recomputed).
    print("\n== integrity gate: --force override ==")
    import tempfile
    _sbl = os.path.join(SBL_DIR, "AM5T-14C025-AF.vbf")
    if os.path.exists(_sbl):
        _raw = bytearray(open(_sbl, "rb").read())
        _good = Vbf(_sbl)
        chk("the pristine SBL passes its own CRCs", not _good.check())
        # Flip one payload byte: breaks both the block CRC-16 and file CRC-32
        # without disturbing the block walk (start/length fields untouched).
        _off = _good.data_start + 8
        _raw[_off] ^= 0xFF
        _tmp = os.path.join(tempfile.gettempdir(), "vbflasher_crcbad.vbf")
        with open(_tmp, "wb") as fh:
            fh.write(_raw)
        _badv = Vbf(_tmp)
        _probs = _badv.check()
        chk("the flipped byte is detected (block CRC-16 + file CRC-32)",
            len(_probs) == 2, "; ".join(_probs))
        try:
            _check_integrity([_badv])
            _refused = False
        except SystemExit:
            _refused = True
        chk("a CRC mismatch is REFUSED without --force", _refused)
        try:
            _check_integrity([_badv], force=True)
            _forced_crc = True
        except SystemExit:
            _forced_crc = False
        chk("--force downgrades the CRC mismatch to a warning", _forced_crc)
        try:
            _check_integrity([_good])
            _clean = True
        except SystemExit:
            _clean = False
        chk("a clean file still passes with no --force", _clean)
        os.unlink(_tmp)
    else:
        print(f"  SKIP  {os.path.basename(_sbl)} not present")

    # Header COMMENTS must never be parsed as declarations. Ford ships the
    # F1FT IPMA calibration with its whole `erase = {...};` block commented
    # out; a raw-header regex resurrects it and the SBL answers the phantom
    # erase with NRC 31 requestOutOfRange.
    print("\n== VBF header comment stripping ==")
    _sc = _vbf.strip_comments
    chk("// line comment removed",
        "erase" not in _sc("a = 1;\r\n  // erase = { { 0x1, 0x2 } };\r\n"))
    chk("/* block */ comment removed",
        "erase" not in _sc("a = 1; /* erase = { { 0x1, 0x2 } }; */ b = 2;"))
    chk("comment stripping preserves length",
        len(_sc("x; // hi\r\ny;")) == len("x; // hi\r\ny;"))
    chk("newlines survive stripping so line structure is intact",
        _sc("x; // hi\r\ny;").endswith("\r\ny;"))
    chk("a // inside a quoted string is NOT treated as a comment",
        'http://x' in _sc('description = { "http://x" };'))
    chk("real (uncommented) erase still parses",
        "erase" in _sc('   erase = { { 0x00003000, 0x00004428 }\r\n };'))
    _f1ft = ("/home/gl/Projects/ford/IPMA/Research/"
             "F1FT-14F398-AG_LKA40_LCA45.VBF")
    if os.path.exists(_f1ft):
        vf = Vbf(_f1ft)
        chk("F1FT calibration declares NO erase (its block is commented out)",
            vf.erase == [], repr(vf.erase))
        chk("F1FT calibration still walks its one block at 0x00902000",
            [(b["start"], b["length"]) for b in vf.blocks]
            == [(0x902000, 0x640D)])
        chk("F1FT calibration container verifies clean", vf.check() == [],
            "; ".join(vf.check()))
    else:
        print(f"  SKIP  {os.path.basename(_f1ft)} not present")
    _cv4t = "/home/gl/Projects/ford/IPMA/Research/CV4T-14F398-AF.VBF"
    if os.path.exists(_cv4t):
        vc = Vbf(_cv4t)
        chk("CV4T calibration (uncommented) keeps its erase region",
            vc.erase == [(0x3000, 0x4428)], repr(vc.erase))
    else:
        print(f"  SKIP  {os.path.basename(_cv4t)} not present")

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
                     "--force", "--test-sbl", "--recovery", "--quiet-bus",
                     "--decompress", "--skip-blank", "--erase-timeout",
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
        sp.add_argument("--iface", default=None,
                        help="override SocketCAN interface (default: HS-CAN=can0, "
                             "MS-CAN=can1)")
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
    s.add_argument("--session", type=lambda x: int(x, 0), default=None,
                   help="enter diagnosticSession first (e.g. 0x03 extended, "
                        "0x02 programming) — some DIDs need it")
    s.add_argument("--unlock", action="store_true",
                   help="SecurityAccess unlock before reading (some DIDs need it)")
    s.add_argument("--secret", type=lambda x: int(x, 0), default=None,
                   help="override the seed-key secret (implies --unlock)")
    s.add_argument("--sec-level", type=lambda x: int(x, 0), default=None,
                   help="SecurityAccess request level (implies --unlock; "
                        "default level 1 when unlocking)")
    s.add_argument("--hw", default=None,
                   help="assume this F111 for secret selection under --unlock")
    s.add_argument("--seed-delay", type=float, default=SEED_DELAY,
                   help="seconds between a --session change and 27 xx "
                        f"requestSeed (default {SEED_DELAY}; 0 disables)")
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
    s.add_argument("--seed-delay", type=float, default=SEED_DELAY,
                   help="seconds between a --session change and 27 xx "
                        f"requestSeed (default {SEED_DELAY}; 0 disables)")
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
        sp.add_argument("--iface", default=None,
                        help="override SocketCAN interface (default: HS-CAN=can0, "
                             "MS-CAN=can1)")
        sp.add_argument("--rxid", type=lambda x: int(x, 0), default=None)
        sp.add_argument("--sbl", default=None,
                        help="explicit SBL VBF path (else auto from F111)")
        sp.add_argument("--sbl-dir", action="append", default=[])
        sp.add_argument("--secret", type=lambda x: int(x, 0), default=None)
        sp.add_argument("--sec-level", type=lambda x: int(x, 0), default=1)
        sp.add_argument("--hw", default=None,
                        help="assume this F111 (skip the live read)")
        sp.add_argument("--seed-delay", type=float, default=SEED_DELAY,
                        help="seconds between session entry and 27 xx "
                             f"requestSeed (default {SEED_DELAY}; 0 disables)")
        sp.add_argument("--addr-len-fmt", type=lambda x: int(x, 0), default=0x44,
                        help="addressAndLengthFormatId (default 0x44 = 4+4)")
        sp.add_argument("--quiet-bus", action="store_true")
        sp.add_argument("--wake-tries", type=int, default=8)
        sp.add_argument("--wake-timeout", type=float, default=0.5)
        sp.add_argument("--tp-interval", type=float, default=TP_INTERVAL)
        sp.add_argument("--progress-interval", type=float, default=1.0)
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
    s.add_argument("--erase-len", type=lambda x: int(x, 0), default=None,
                   help="bytes to erase (31 01 FF00), independent of the data "
                        "size. The ECU erases whole flash sectors and rejects "
                        "a short length with requestOutOfRange (0x31). "
                        "e.g. BCM CCC needs 0x4000 for DV6T/F1FT/F1DT (0x400 "
                        "for BV6N), IPC 0x1000. Default: the data size.")
    s.add_argument("--no-verify", action="store_true",
                   help="skip the 31 01 0304 verify routine after writing")

    s = sub.add_parser("flash", help="flash one or more VBF files")
    s.add_argument("vbf", nargs="*", metavar="FILE|ECU",
                   help="VBF file(s) to upload. Multiple allowed; grouped by "
                        "ecu_address. SBL-type files are used as the SBL. "
                        "With --test-sbl there is nothing to flash, so an ECU "
                        "name or id may be given instead (e.g. GWM).")
    s.add_argument("--iface", default=None,
                   help="override SocketCAN interface (default: HS-CAN=can0, "
                        "MS-CAN=can1)")
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
    s.add_argument("--recovery", action="store_true",
                   help="skip live identity/wake reads and repeatedly send "
                        "10 02 to catch the PBL after power-up; requires "
                        "--hw or both --sbl and --secret (Ctrl-C to stop)")
    s.add_argument("--dry-run", "-n", action="store_true",
                   help="print the plan only; connect to nothing, send nothing")
    s.add_argument("--yes", "-y", action="store_true",
                   help="skip the 'are you sure?' confirmation (for scripting)")
    s.add_argument("--force", action="store_true",
                   help="downgrade refusals to warnings: a VBF checksum "
                        "mismatch (block CRC-16 / file CRC-32), an EXE "
                        "identity mismatch, and a flash-order overlap where a "
                        "later part's erase covers an earlier part's blocks")
    s.add_argument("--quiet-bus", action="store_true",
                   help="silence other modules for the flash (functional "
                        "10 82; unconfirmed, network-wide; off by default)")
    s.add_argument("--decompress", action="store_true",
                   help="LZSS-expand a compressed payload on the host and "
                        "transmit it in plain (34 00 ... with the UNPACKED "
                        "length) instead of sending the on-disk compressed "
                        "bytes with dfi 0x10. Only for a boot loader that "
                        "cannot decompress; the proven Ford path is verbatim.")
    s.add_argument("--skip-blank", nargs="?", type=lambda x: int(x, 0),
                   const=0x1000, default=0, metavar="BYTES",
                   help="speed up the download by NOT transmitting runs of "
                        "0xFF at least BYTES long (default 4096 when the flag "
                        "is given bare) that the part's own erase map already "
                        "leaves blank: the block is split into several "
                        "downloads around them. A compressed part is expanded, "
                        "split and RE-PACKED, so it still goes on the wire as "
                        "dfi 0x10 (add --decompress to send it plain instead). "
                        "Refused unless the split is proven lossless by "
                        "reassembly.")
    s.add_argument("--blank-byte", type=lambda x: int(x, 0), default=0xFF,
                   help="erased-flash byte for --skip-blank; only 0xFF is "
                        "supported (other values are refused for safety)")
    s.add_argument("--seed-delay", type=float, default=SEED_DELAY,
                   help=f"seconds to wait between entering the programming "
                        f"session and 27 xx requestSeed (default "
                        f"{SEED_DELAY}; UCDS waits ~1 s while the module "
                        f"enters its bootloader). 0 disables.")
    s.add_argument("--erase-timeout", type=float, default=60.0,
                   help="seconds of SILENCE that ends an erase/finalise wait")
    s.add_argument("--wake-tries", type=int, default=8,
                   help="3E 00 wake attempts for a sleeping bus (default 8)")
    s.add_argument("--wake-timeout", type=float, default=0.5,
                   help="seconds per wake attempt (default 0.5)")
    s.add_argument("--progress-interval", type=float, default=1.0,
                   help="progress refresh interval in seconds "
                        "(default 1.0)")
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
