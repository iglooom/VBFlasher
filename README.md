# VBFlasher — multi-ECU Ford VBF flasher

One CLI that flashes any registered Ford ECU over UDS/ISO-TP (SocketCAN). The
target ECU, its SecurityAccess secret, and its Secondary Bootloader (SBL) are
selected automatically from the module's own **F111** (hardware / Core Assembly
Number). Built by consolidating three hardware-proven flashers (BCM, PSCM,
IPMA) plus the OEM-derived secret/SBL tables from FoCCCus `ford_c346.cpp`.

## Files

| file | role |
|---|---|
| `vbflasher.py` | the CLI (parse, plan, confirm, flash) |
| `ecu_db.py` | **the only place ECU-specific data lives** — addresses, secrets, SBLs, quirks |
| `ford_seckey.py` | the one universal seed→key algorithm (5-byte secret, big-endian) |
| `vbf.py` | VBF container parser + ISO-TP transport + bus-quiet / keepalive / download |

The seed→key algorithm is identical across every Ford ECU here; only the 5-byte
**secret** and the **SBL** differ. This was proven: keys computed from the
registry secrets are byte-identical to those from the proven BCM/PSCM/IPMA
tools (`vbflasher.py --selftest` asserts it).

## Usage

```bash
python3 vbflasher.py --selftest                      # offline self-tests
python3 vbflasher.py list                            # registered ECUs
python3 vbflasher.py info   FILE.vbf [...]           # header + block table + integrity
python3 vbflasher.py verify FILE.vbf [...]           # CRC check only
python3 vbflasher.py ident  BCM                      # read a live module's IDs (name or id)
python3 vbflasher.py ident  ALL                      # iterate every module, print each ident

# DTCs — no VBF needed; select ECU by name or CAN id
python3 vbflasher.py dtc      BCM                     # actual faults only (default)
python3 vbflasher.py dtc      ALL                     # per-module actual-DTC count overview
python3 vbflasher.py dtc      BCM --all               # include 'not completed' entries
python3 vbflasher.py dtc      7E0                     # by CAN id (PCM)
python3 vbflasher.py dtc      PCM --status-mask 0x08  # only confirmed DTCs
python3 vbflasher.py cleardtc BCM                     # clear one module (asks y/N)
python3 vbflasher.py cleardtc 0x730 --yes             # clear, no prompt

# reset a module (11 01 hardReset by default)
python3 vbflasher.py reset    BCM                     # hard reset one module
python3 vbflasher.py reset    PCM --mode 0x03         # soft reset

# ALL modules at once, via functional 0x7DF broadcast (unconfirmed)
python3 vbflasher.py cleardtc ALL --yes               # clear DTCs on every module
python3 vbflasher.py reset    ALL --yes               # reboot every module
python3 vbflasher.py reset    7DF --yes               # same (id form of ALL)

# dry run prints the full plan and connects to nothing
python3 vbflasher.py flash  APP.vbf --dry-run
python3 vbflasher.py flash  APP.vbf                   # live; asks "are you sure? [y/N]"
python3 vbflasher.py flash  APP.vbf CAL.vbf           # several files in one session
python3 vbflasher.py flash  APP.vbf --yes             # skip the prompt (scripting)
python3 vbflasher.py flash  APP.vbf --test-sbl        # load+run SBL only, no erase/write
```

By default you give only VBF file(s): the ECU is read from each file's
`ecu_address`, and the SBL + secret come from the internal database keyed on the
live F111. The SBL VBF is looked up in the `sbl/` subdir (then beside the
flasher); if it is missing the
tool tells you exactly which file to supply.

Key flags: `--iface can0` (default), `--dry-run/-n` (plan only, opens no
socket), `--yes/-y` (skip the confirmation prompt), `--sbl PATH` (override the
auto-selected SBL), `--sbl-dir DIR` (extra search dir, repeatable), `--secret
0x...` (override the seed-key secret), `--sec-level N` (diag security level;
secrets can differ per level), `--hw STRING` (assume an F111 for dry-run
planning), `--test-sbl`, `--quiet-bus`, `--force`, `--rxid`, `--erase-timeout`,
`--tp-interval`, `--tp-id`, `--logfile`.

## Flow

1. Parse **and fully verify** every VBF (block CRC-16 + file CRC-32) before any
   byte reaches the ECU. Files are grouped by `ecu_address` into sessions.
2. Connect, read **F111** and the other identity DIDs (printed as "current
   firmware").
3. From F111: pick the SBL VBF and the secret from `ecu_db`. Missing SBL ⇒ stop
   with instructions. `--sbl`/`--secret` override.
4. Print the **plan**: SBL, what is erased, what is written, current firmware
   IDs. Ask **"Are you sure? [y/N]"** (skip with `--yes`).
5. On `y`: `10 02` → `27 01/02` (seed-key) → download+start SBL → per region
   `31 01 FF00` erase → `34/36/37` download → optional `31 01 0304` finalise →
   `11 01` reset. `--test-sbl` stops right after the SBL starts.

Safety: a plan is always printed and gated behind a `y/N` prompt (`--dry-run`
opts out and opens no socket; `--yes` skips the prompt for scripting); DLC=8
padding (Ford ignores short frames); `0x78`
responsePending treated as CONTINUE with a clock that restarts on each pending;
EXE parts gated on F188==VBF part (DATA/calibration reported only); `--quiet-bus`
is opt-in and unconfirmed.

## Adding a new ECU

Append one `EcuProfile` to `ECUS` in `ecu_db.py` — nothing else changes:

```python
0x7XX: EcuProfile(
    name="MY ECU", txid=0x7XX, rxid=0x7XX+8,     # rxid defaults to txid+8
    secrets=(
        SecretRule("HWPREFIX", 1, "AABBCCDDEE"),  # by F111 prefix + sec level
        SecretRule("", None, "0000000000"),       # ''=any prefix, None=any level
    ),
    sbls=(SblRule("HWPREFIX", "MY-SBL.vbf"),),     # by F111 prefix
    default_sbl="MY-SBL.vbf",                      # fallback
    finalize=True,          # run 31 01 0304 before reset (PCM/TCM/ABS/PSCM/IPMA)
    sbl_call_halfword=False,# True => start SBL with high 16 bits only (IPMA)
)
```

Registered today: IPC 0x720, BCM 0x726, ACM 0x727, PSCM 0x730, DEATC/HVAC
0x733, RCM 0x737, ABS 0x760, FCDIM 0x7A5, PCM 0x7E0, TCM 0x7E1, IPMA 0x706.

## Provenance

Secrets/SBLs: FoCCCus `ford_c346.cpp` (`getSecret`, `getSblFilename`, keyed on
F111). Hardware-relevant, matching the working per-ECU flashers verbatim: BCM
`64000B0C59` (verified), PSCM `00009B2533` (published, unverified on the module
— treat the first live `27 02` as the test), IPMA `00009875CA` (solved from two
captured sessions).
