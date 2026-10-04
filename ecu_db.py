#!/usr/bin/env python3
"""ECU registry for VBFlasher — the ONLY place ECU-specific knowledge lives.

Adding a new ECU is a single EcuProfile entry in ECUS below; nothing else in
vbflasher.py hardcodes an address, secret, SBL or routine quirk.

Provenance of the data in this file
------------------------------------
* SecurityAccess secrets and SBL filenames come from the FoCCCus project
  (/home/gl/Dropbox/focus/FoCCCus/ford_c346.cpp getSecret()/getSblFilename()),
  which selects both from the F111 hardware/assembly string exactly as the
  design here does.
* Three secrets are additionally HARDWARE-relevant to this workspace and match
  the working per-ECU flashers verbatim:
      BCM  0x726  level1  64000B0C59   (verified on the bench BCM)
      PSCM 0x730  level1  00009B2533   (published; UNVERIFIED on the module)
      IPMA 0x706  level1  00009875CA   (solved from two captured flash sessions;
                                        works on both CV4T and F1FT modules)
      IPMA 0x706  level3  0000E727FB   (solved from two captured UCDS Direct
                                        Configuration sessions on F1FT-14F403-AE,
                                        seeds 3636B8/1C8ABA; required even to
                                        READ the config DIDs. See
                                        IPMA/Research/IPMA_camera_alignment.md)
      IPC  0x720  level3  0102030405   (DM5T-14F094 application: stored in
                                        live RAM at 0x400086D3 and confirmed
                                        from captured seed/key pairs)
      IPC  0x720  level1  EC6D038211   (DM5T-14F094 PBL: unlocked the live
                                        module and recovered the stock MCU
                                        application; the earlier 381-candidate
                                        miss was against the application, not
                                        this PBL security context)
      ABS  0x760  level1  42434D5932   (accepted in four FORScan flashes and
                                        recoveries; distinct captured seeds
                                        and keys have regression tests)
      CCM  0x764  level1  AACCCC3355   (keybag value, CONFIRMED by the UCDS
                                        flash capture CCM/GV6T/ucds_flash.log:
                                        seed AC47B6 -> key E0876D was accepted
                                        with 67 02)
* The seed->key algorithm is a SINGLE universal LFSR keygen parameterised by a
  5-byte big-endian secret. keygen_equivalence proved BCM==PSCM==IPMA keys are
  byte-identical under that mapping, so a per-ECU keygen is never needed — only
  the secret and SBL change.

A "secret" here is the 5-byte value fed to the keygen, most-significant byte
first (the FoCCCus QByteArray order). The keygen treats it big-endian.
"""
from dataclasses import dataclass, field
from typing import Optional


BUS_DEFAULT_IFACES = {
    "HS-CAN": "can0",
    "MS-CAN": "can1",
}


@dataclass
class SecretRule:
    """One secret, chosen by F111 hardware-string prefix and diag security level.

    hw_prefix : match when the live F111 string startswith this (''=any).
    level     : SecurityAccess level the secret is for (odd request level:
                1 = requestSeed 0x27 01, 3 = 0x27 03 ...). None = any level.
    secret    : 5 bytes, MSB first (as printed by FoCCCus fromHex()).
    """
    hw_prefix: str
    level: Optional[int]
    secret: str


@dataclass
class SblRule:
    """SBL VBF filename chosen by F111 hardware-string prefix (''=any/default)."""
    hw_prefix: str
    filename: str


@dataclass
class EcuProfile:
    name: str
    txid: int                       # diagnostic request CAN ID
    bus: str                        # physical diagnostic bus: HS-CAN or MS-CAN
    rxid: Optional[int] = None      # response ID; default txid + 8 (Ford)
    aliases: tuple = ()             # short names, e.g. ("BCM",) — for CLI select
    # DIDs read (report only) at flash time; F111 drives SBL+secret selection.
    ident_dids: tuple = ("F188", "F120", "F124", "F125", "F108", "F10A", "F111", "F113",
                         "F18C", "F190")
    # Which DID carries the SOFTWARE part number, per VBF sw_part_type. EXE is
    # gated on equality with the VBF part; DATA is REPORT-ONLY (calibration part
    # numbers legitimately differ from F188/F124 — the IPMA lesson).
    ident_did_by_type: dict = field(default_factory=lambda: {"EXE": "F188",
                                                             "DATA": "F124",
                                                             "SBL": "F188"})
    secrets: tuple = ()             # tuple[SecretRule]
    sbls: tuple = ()                # tuple[SblRule]
    default_sbl: Optional[str] = None   # fallback SBL when no hw_prefix matches
    # SBL is started with routine 0301. Ford tools send the 4-byte call address;
    # the IPMA ground-truth capture sends only the HIGH 16 bits. Per-ECU.
    sbl_call_halfword: bool = False
    # Run routine 0304 (checkProgrammingDependencies / finalise) after the last
    # TransferExit and before reset. The DM5T IPC PBL stamps its boot marker here.
    finalize: bool = False
    # Some PBLs return a status after the positive routine response. Merely
    # seeing SID 71 is not proof that the application was accepted for boot.
    finalize_response: Optional[bytes] = None
    # Exact programming-session reply from the PBL, when known. In recovery,
    # a custom application may also answer 50 02 but cannot flash memory.
    recovery_session_response: Optional[bytes] = None
    # Optional start-SBL routine response from the proven PBL. A custom
    # application may return a shorter 71 01 03 01 without starting the SBL.
    sbl_start_response: Optional[bytes] = None
    # This bootloader answers 37 RequestTransferExit with `77 <crc16>` over the
    # bytes it received, so the echo can be checked against the file. Set only
    # where a capture proves it; a bare `77` is normal elsewhere. A MISMATCHED
    # echo aborts on every ECU — this flag only makes its ABSENCE an error.
    transfer_exit_crc: bool = False

    def resp_id(self):
        return self.rxid if self.rxid is not None else self.txid + 8

    def default_iface(self):
        """Return the SocketCAN interface assigned to this ECU's physical bus."""
        try:
            return BUS_DEFAULT_IFACES[self.bus]
        except KeyError:
            raise ValueError(f"unsupported CAN bus {self.bus!r} for {self.name}")

    def pick_secret(self, hw: str, level: int) -> Optional[bytes]:
        hw = hw or ""
        # exact level first, then level-agnostic, longest prefix wins
        for want_level in (level, None):
            best = None
            for r in self.secrets:
                if r.level != want_level:
                    continue
                if hw.startswith(r.hw_prefix):
                    if best is None or len(r.hw_prefix) > len(best.hw_prefix):
                        best = r
            if best is not None:
                return bytes.fromhex(best.secret)
        return None

    def pick_sbl(self, hw: str) -> Optional[str]:
        hw = hw or ""
        best = None
        for r in self.sbls:
            if r.hw_prefix and hw.startswith(r.hw_prefix):
                if best is None or len(r.hw_prefix) > len(best.hw_prefix):
                    best = r
        if best is not None:
            return best.filename
        # then a blank-prefix (catch-all) SBL rule, then the profile default
        for r in self.sbls:
            if r.hw_prefix == "":
                return r.filename
        return self.default_sbl


# --------------------------------------------------------------------------
# The registry.  Keyed by diagnostic request CAN ID (== VBF ecu_address).
# --------------------------------------------------------------------------
ECUS = {
    0x720: EcuProfile(
        name="IPC (instrument cluster)", txid=0x720, bus="MS-CAN",
        aliases=("IPC",),
        secrets=(
            SecretRule("", 1, "621C067260"),
            SecretRule("", 3, "8408F57701"),
            SecretRule("EJ7T-14F094", 3, "0000DCBF06"),
            SecretRule("EJ7T-14F094", 1, "00004A7722"),
            SecretRule("DM5T-14F094", 3, "0102030405"),
            SecretRule("DM5T-14F094", 1, "EC6D038211"),
        ),
        sbls=(
            SblRule("BM5T-14C226-C", "BM5T-14C025-AD.vbf"),
            SblRule("BM5T-14C226-A", "BM5T-14C025-AD.vbf"),
            SblRule("BM5T-14C226-B", "BM5T-14C025-BD.vbf"),
            SblRule("CM5T-14C226-B", "BM5T-14C025-BD.vbf"),
            SblRule("CM5T-14C226-EA", "CM5T-14C025-AC.vbf"),
            SblRule("CV4T-14F094-B", "CV4T-14C025-BC.vbf"),
            SblRule("F1ET-14F094-A", "F1ET-14C025-AB.vbf"),
            SblRule("GJ5T-14F094-B", "GJ5T-14C025-BB.vbf"),
            SblRule("EJ7T-14F094", "DP5T-14C025-CA.vbf"),
            SblRule("DM5T-14F094", "FM5T-14C025-AA.vbf"),
        ),
        # DM5T PBL writes its application boot-commit marker only after this
        # routine succeeds; without it the next reset returns to the PBL.
        # The same six-byte success response is captured on an EJ7T IPC.
        finalize=True,
        finalize_response=bytes.fromhex("710103041002"),
    ),
    0x726: EcuProfile(
        name="BCM (body control)", txid=0x726, bus="HS-CAN", rxid=0x72E,
        aliases=("BCM",),
        secrets=(
            SecretRule("BV6N", None, "F311454C73"),
            SecretRule("AV6N", None, "F311454C73"),
            SecretRule("DV6T", 1, "64000B0C59"),
            SecretRule("DV6T", 3, "CD0D52F64D"),
            SecretRule("F1FT", 1, "64000B0C59"),
            SecretRule("F1FT", 3, "CD0D52F64D"),
            SecretRule("F1DT", 1, "64000B0C59"),
            SecretRule("F1DT", 3, "CD0D52F64D"),
        ),
        sbls=(
            SblRule("AV6N-14C245", "AV6N-14C097-AB.vbf"),
            SblRule("BV6N-14C245", "BV6N-14C097-AC.vbf"),
            SblRule("DV6T-14C245", "DV6T-14C097-AB.vbf"),
            SblRule("F1FT-14F119", "F1FT-14C097-AA.vbf"),
            SblRule("F1DT-14F119", "F1DT-14C097-AA.vbf"),
        ),
        default_sbl="DV6T-14C097-AB.vbf",
    ),
    0x727: EcuProfile(
        name="ACM (audio)", txid=0x727, bus="MS-CAN", aliases=("ACM",),
        secrets=(SecretRule("", None, "13F129B301"),),
        sbls=(SblRule("BM5T-14C230", "AM5T-14C047-DC.vbf"),),
        finalize=True,
    ),
    0x730: EcuProfile(
        name="PSCM (electric power steering)", txid=0x730, bus="HS-CAN",
        rxid=0x738, aliases=("PSCM", "EPAS"),
        secrets=(SecretRule("", 1, "00009B2533"),),
        default_sbl="BV6T-14C220-AA.vbf",
        finalize=True,
    ),
    0x764: EcuProfile(
        # Delphi ESR forward radar; also runs the ACC state machine.
        # Host CPU is V850 (GV6T-14D049-xx), plus a TI DSP (GV6T-14G012-AA).
        # SBL AE9T-14D051-AA loads to RAM at 0x03FF9000.
        name="CCM (cruise control module / ESR radar)", txid=0x764,
        bus="HS-CAN", rxid=0x76C, aliases=("CCM", "ESR", "ACC"),
        # GROUND TRUTH: UCDS flash captures in CCM/GV6T/. ucds_flash.log holds
        # the full prologue (an AD downgrade), uscds.log the BD download:
        #   22 F113 -> AG9N-9G768-BF      (hardware part; this module answers
        #                                  F113, NOT F111 — hw stays '' here,
        #                                  so keep every rule prefix blank)
        #   22 F188 -> GV6T-14D049-BD
        #   7DF 02 10 82  x71 @ ~50 ms, then 10 02 ~50 ms later
        #   10 02   -> 50 02 00 19 01 F4
        #   (UCDS waits ~1.0 s here before requestSeed)
        #   27 01   -> 67 01 AC47B6 ; 27 02 E0876D -> 67 02   (secret verified)
        #   34 00 44 03FF9000 00001500 -> 74 20 0082   (128-byte transfers)
        #   36 x42 (= 0x1500, byte-identical to sbl/AE9T-14D051-AA.vbf)
        #   37      -> 7F 37 78 then 77 C404
        #   31 01 0301 03FF9000 -> 71 01 0301 10       (FULL 4-byte call addr)
        #   31 01 FF00 00008000 00058000 -> 7F 31 78, 71 01 FF00 10
        #   31 01 FF00 00FF8000 00004000 -> 71 01 FF00 10
        #   31 01 FF00 00FFC800 00003800 -> 71 01 FF00 10
        #   34 00 44 00008000 00058000 -> 74 20 0082, then 36 x2816
        #   37      -> 77 226F        (= block 0's stored CRC-16)
        #   34 00 44 00FFC800 00003800 -> 74 20 0082, then 36 x112
        #   37      -> 77 DDEF        (= block 1's stored CRC-16)
        #   31 01 0304 -> 71 01 0304 10 02    (finalise ACCEPTED)
        #   11 01   -> 51 01
        #   keepalive: 7DF 02 3E 80 every ~2.0 s; the rest of the bus keeps
        #   transmitting normally throughout, so the 10 82 arm silences little.
        # Every 37 echoes `77 <crc16>` over the bytes the module received, and
        # all three matched the VBF's own stored block CRC (SBL C404, app 226F
        # and DDEF) -> a free end-to-end verification, enforced here.
        # Each 36 answers 7F 36 78 then 76 <seq> ~185 ms later: 0.68 KiB/s, so
        # the whole 366 KiB part took ~9.1 min on the wire. seq wraps FF -> 00.
        # The final 37 of block 0 went pending for 3.05 s; finalise took 0.47 s.
        default_sbl="AE9T-14D051-AA.VBF",
        # Level 1 is capture-verified. No other level has been captured; the
        # level-agnostic rule stays as the keybag fallback for those.
        secrets=(
            SecretRule("", 1, "AACCCC3355"),
            SecretRule("", None, "AACCCC3355"),
        ),
        sbl_call_halfword=False,
        recovery_session_response=bytes.fromhex("5002001901F4"),
        sbl_start_response=bytes.fromhex("7101030110"),
        finalize=True,
        finalize_response=bytes.fromhex("710103041002"),
        transfer_exit_crc=True,
    ),
    0x706: EcuProfile(
        name="IPMA (front camera)", txid=0x706, bus="HS-CAN", rxid=0x70E,
        aliases=("IPMA",),
        ident_dids=("F113", "F188", "F120", "F124", "F125", "F108", "F10A",
                    "F111", "F18C", "F190"),
        # level 1 = flash/programming (27 01/02). level 3 = the Direct
        # Configuration DID set (27 03/04), which the IPMA requires even to
        # READ D700/D701/DE00-DE03/FD05-FD08. Keep the level-agnostic rule last
        # so any other level still resolves to the flash secret as before.
        secrets=(
            SecretRule("", 3, "0000E727FB"),
            SecretRule("", None, "00009875CA"),
        ),
        default_sbl="CV4T-14F399-AF.VBF",
        sbl_call_halfword=False,
        finalize=True,
    ),
    0x737: EcuProfile(
        name="RCM (restraints)", txid=0x737, bus="HS-CAN", aliases=("RCM",),
        secrets=(
            SecretRule("", 3, "50000A241D"),
            SecretRule("", None, "0000000000"),
        ),
        finalize=True,
    ),
    0x760: EcuProfile(
        name="ABS", txid=0x760, bus="HS-CAN", aliases=("ABS",),
        # FORScan 0x760/0x768 captures in ford/ABS/forscan_*.log: four
        # independent level-1 seeds were unlocked with this existing secret.
        # No F111 was read in those logs, so do not invent an F111 prefix.
        # The level-agnostic FoCCCus rule remains as the legacy fallback;
        # only level 1 is independently proven by these captures.
        secrets=(
            SecretRule("", 1, "42434D5932"),
            SecretRule("", None, "42434D5932"),
        ),
        sbls=(
            SblRule("BV61-14C227", "BV61-14C039-AA.vbf"),
            SblRule("F1FC-14F067", "E3B1-14C039-AA.vbf"),
        ),
        # All four captures transferred the BV61 SBL to 0x004003AC and
        # received 71 01 03 01 10 after starting it. Both full-application
        # and SIGCFG recoveries ended with 71 01 03 04 10 02, followed by
        # D100 changing from 02 to 01. These signatures are only evidenced
        # for the captured CV61/BV61 bootloader, NOT the F1FC variant; do not
        # impose profile-wide recovery/finalise response gates on both.
        #
        # FINALISE IS REQUIRED and is already on: 31 01 0304 -> 71 01 0304 10 02
        # appears in forscan_flash2, forscan_recovery and forscan_recovery2
        # (flash_mod's capture stops before it). It answers instantly, unlike
        # the CCM's 0.47 s. A functional 11 81 reset follows, then D100 flips
        # 02 -> 01 — that DID is a post-flash readback worth polling.
        #
        # This bootloader ALSO echoes a CRC-16 in 37 RequestTransferExit, and
        # it is the VBF's own stored block CRC. Verified against the files:
        #   77 2D63  BV61-14C039-AA   SBL  @0x004003AC len 0x4F4
        #   77 2079  CV61-14C381-AH   blk0 @0x00020000 len 0x4000
        #   77 919E  CV61-14C381-AE   blk0 @0x00020000 len 0x4000
        #   77 F1D1 / 5008 / EEC2 / E490   CV61-14C036-AH blk0..blk4
        # forscan_flash_mod echoed 3631 and EB59 for the 0xD8668 application
        # and the 0xFFFFFF02 trailer: an AH-derived PATCHED build that is not
        # any file currently on disk (AH-gate04 would give 47B9/292C). So the
        # echo pins down exactly which image is on the module.
        # transfer_exit_crc is deliberately NOT set here: that flag only makes
        # a MISSING echo an error, and absence is unproven for the F1FC
        # bootloader. The mismatch check runs unconditionally, so ABS already
        # gets the verification without risking a refused F1FC flash.
        # maxNumberOfBlockLength is 74 20 03FF -> 1021 payload bytes/transfer.
        finalize=True,
    ),
    0x7A5: EcuProfile(
        name="FCDIM / FDIM (display)", txid=0x7A5, bus="MS-CAN",
        aliases=("FCDIM", "FDIM"),
        secrets=(
            SecretRule("CM5T-14F180-C", None, "50C86A49F1"),
            SecretRule("BM5T-14D356-C", None, "50C86A49F1"),
            SecretRule("", None, "08306155AA"),
        ),
        sbls=(
            SblRule("AM5T-14D356-A", "AM5T-14D360-AB.vbf"),
            SblRule("AM5T-14D356-C", "AM5T-14D360-CB.vbf"),
            SblRule("AM5T-14D356-B", "BM5T-14D360-BB.vbf"),
            SblRule("DM5T-14D356-G", "DM5T-14D360-CA.vbf"),
            SblRule("BM5T-14D356-C", "BM5T-14D360-CA.vbf"),
            SblRule("CM5T-14F180-C", "BM5T-14D360-CB.vbf"),
        ),
    ),
    0x7D0: EcuProfile(
        name="APIM", txid=0x7D0, bus="MS-CAN",
        aliases=("APIM"),
        secrets=(
            SecretRule("", 3, "9A78563412"),
            SecretRule("", 1, "50C86A49F1"),
        ),
        sbls=(
        ),
    ),
    0x7E0: EcuProfile(
        name="PCM (engine)", txid=0x7E0, bus="HS-CAN", rxid=0x7E8,
        aliases=("PCM", "ECM"),
        secrets=(
            SecretRule("AV61-12B684", 1, "A3B2C01492"),
            SecretRule("AV61-12B684", 3, "2431DEF946"),
            SecretRule("BV61-12B684-D", None, "083061A4C5"),
            SecretRule("CV6A-12B684", None, "083061A4C5"),
        ),
        sbls=(
            SblRule("AV61-12B684", "AV61-14C273-AA.vbf"),
            SblRule("BV61-12B684-D", "BB5A-14C273-AA.vbf"),
            SblRule("CV6A-12B684", "DL3A-14C273-AA.vbf"),
        ),
        finalize=True,
    ),
    0x7E1: EcuProfile(
        name="TCM (transmission)", txid=0x7E1, bus="HS-CAN", rxid=0x7E9,
        aliases=("TCM",),
        secrets=(SecretRule("", None, "415249414E"),),
        sbls=(SblRule("AE8P-14F085", "AE8P-7J244-AB.vbf"),),
        finalize=True,
    ),
    0x733: EcuProfile(
        name="DEATC / HVAC", txid=0x733, bus="MS-CAN",
        aliases=("DEATC", "HVAC"),
        secrets=(SecretRule("", None, "415249414E"),),
        sbls=(SblRule("AM5T-14C239", "AM5T-18D618-BB.vbf"),),
    ),
    0x716: EcuProfile(
        name="GWM", txid=0x716, bus="HS-CAN", aliases=("GWM",),
        secrets=(
            SecretRule("", 1, "0000F64E88"),
            SecretRule("", 3, "00000D14EF"),
        ),
        sbls=(SblRule("", "CM5T-14F532-AA.vbf"),),
        ident_did_by_type={"EXE": "F188", "DATA": "F124",
                           "SIGCFG": "F108", "SBL": "F188"},
        finalize=True,
        # Captured PBL replies 50 02 00 19 01 F4; the custom application
        # replies 50 02 00 32 01 F4 and does not successfully flash.
        recovery_session_response=bytes.fromhex("5002001901F4"),
        # The PBL reports status 0x10 after launching the SBL. The custom
        # application responds 71 01 03 01 but never reaches the SBL erase.
        sbl_start_response=bytes.fromhex("7101030110"),
    ),
}


def get_profile(txid: int) -> Optional[EcuProfile]:
    return ECUS.get(txid)


def resolve(selector) -> Optional[EcuProfile]:
    """Resolve an ECU from a name alias ('PCM', 'bcm') or a CAN id.

    Accepts: an int (0x726 / 1830), a hex/dec string ('726', '0x726', '7E0'),
    or a case-insensitive name alias. Returns the EcuProfile or None.
    """
    if isinstance(selector, int):
        return ECUS.get(selector)
    s = str(selector).strip()
    if not s:
        return None
    # name alias (case-insensitive) — check before numeric, but a bare hex
    # token like '7E0' is also a valid alias-free id, so try alias first only
    # for non-pure-hex tokens... simplest: alias match wins if it exists.
    up = s.upper()
    for p in ECUS.values():
        if up == p.name.split()[0].upper() or up in {a.upper() for a in p.aliases}:
            return p
    # numeric id: accept 0x-prefixed hex, or bare hex (Ford diag IDs are hex)
    try:
        if s.lower().startswith("0x"):
            return ECUS.get(int(s, 16))
        # try hex first (matches CLI examples '726', '7E0'), then decimal
        for base in (16, 10):
            try:
                v = int(s, base)
            except ValueError:
                continue
            if v in ECUS:
                return ECUS[v]
        return None
    except ValueError:
        return None

