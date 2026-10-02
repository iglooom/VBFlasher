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
      IPMA 0x706          00009875CA   (solved from two captured sessions)
      IPC  0x720  level3  0102030405   (DM5T-14F094 application: stored in
                                        live RAM at 0x400086D3 and confirmed
                                        from captured seed/key pairs)
      IPC  0x720  level1  EC6D038211   (DM5T-14F094 PBL: unlocked the live
                                        module and recovered the stock MCU
                                        application; the earlier 381-candidate
                                        miss was against the application, not
                                        this PBL security context)
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
        # NOT YET VERIFIED against a live module or a UCDS capture: rxid is the
        # Ford txid+8 convention, and no secret/SBL rule is claimed here.
        # Reads (22) need neither, so `readdid` is safe; flashing this ECU
        # requires a SecretRule + SBL established from ground truth first.
        default_sbl="AE9T-14D051-AA.VBF",
    ),
    0x706: EcuProfile(
        name="IPMA (front camera)", txid=0x706, bus="HS-CAN", rxid=0x70E,
        aliases=("IPMA",),
        ident_dids=("F113", "F188", "F120", "F124", "F125", "F108", "F10A",
                    "F111", "F18C", "F190"),
        secrets=(SecretRule("", None, "00009875CA"),),
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
        secrets=(SecretRule("", None, "42434D5932"),),
        sbls=(
            SblRule("BV61-14C227", "BV61-14C039-AA.vbf"),
            SblRule("F1FC-14F067", "E3B1-14C039-AA.vbf"),
        ),
        finalize=True,
    ),
    0x7A5: EcuProfile(
        name="FCDIM / FDIM (display)", txid=0x7A5, bus="MS-CAN",
        aliases=("FCDIM", "FDIM", "APIM"),
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

