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
| `ford_seckey.py` | the universal Ford seed→key LFSR (3-byte seed, 5-byte secret, big-endian) |
| `cgea_seckey.py` | CGEA IPMA HMAC-SHA1 keygens (16-byte seed; PBL level 1, application level 3) |
| `vbf.py` | VBF container parser + ISO-TP transport + bus-quiet / keepalive / download |
| `ford_keybag.py` | 343 candidate secrets transcribed from FoCCCus `bruteSecretKey()` |
| `ford_brutekey.py` | dictionary attack on an unknown SecurityAccess secret (`--self-test` for the offline proof) |
| `vbflasher_gui.py` | PySide6 GUI over everything above — see [GUI](#gui) |
| `gui_backend.py` | Qt-free bus helpers the GUI runs in-process (ident, DID read/write, DTC, reset) |
| `defs.py` | module definitions: pick the DID layouts for a live module, field codec, CCC image, UCDS XML I/O |
| `defs/vbflasher_defs.sqlite` | generated definition DB (DIDs/fields/enums, DTC text, CCF central config) |
| `tools/build_defs.py` | rebuilds `defs/vbflasher_defs.sqlite` from `~/Projects/ford/IDSdb/build` |
| `tools/backup2vbf.py` | rebuilds flashable VBFs from a `backup` directory using OEM VBFs as layout templates (`--layout oem` / `erase`) |
| `sbl/` | Secondary Bootloader VBFs looked up by the registry (the only VBFs tracked in git) |
| `.tests/` | offline unit tests, all CAN transport mocked (git-ignored, local only; see [Tests](#tests)) |
| `logs/` | per-run trace logs (git-ignored) |
| `backups/` | default `backup` output (one directory per run, `manifest.json`) |

The seed→key algorithm is identical across every Ford ECU here except the CGEA
IPMA (`SecretRule.algo`, see [CGEA IPMA](#cgea-ipma-jx7t-14f403-focus-mk4--fiesta-mca-camera));
otherwise only the 5-byte **secret** and the **SBL** differ. This was proven: keys computed from the
registry secrets are byte-identical to those from the proven BCM/PSCM/IPMA
tools (`vbflasher.py --selftest` asserts it).

## Install (user-level CLI)

Symlink the script onto your `PATH` so it runs as `vbflasher` from anywhere:

```bash
chmod +x vbflasher.py
mkdir -p ~/.local/bin
ln -sf "$PWD/vbflasher.py" ~/.local/bin/vbflasher   # ensure ~/.local/bin is on PATH
vbflasher --selftest
```

The script resolves its own real path (`realpath`), so the symlink still finds
its sibling modules (`ecu_db.py`, `vbf.py`) and the `sbl/` folder. It needs only
Python 3 stdlib. Everywhere below, `python3 vbflasher.py` and `vbflasher` are
interchangeable.

### Tab completion (bash / zsh)

Completion is generated **from the live parser + ECU registry**, so it never
drifts from the real subcommands, flags, or ECU names. Install it once:

```bash
vbflasher completion bash --install      # -> ~/.local/share/bash-completion/completions/vbflasher
# or
vbflasher completion zsh  --install      # -> ~/.zsh/completions/vbflasher.zsh
```

Then activate it. For **bash**, open a new shell (needs the `bash-completion`
package). For **zsh**, add ONE `source` line to the *end* of `~/.zshrc`, after
your existing `compinit`:

```zsh
source ~/.zsh/completions/vbflasher.zsh
```

The zsh script registers itself with `compdef`, so sourcing it needs **no extra
`compinit` and no `~/.zcompdump` rebuild** — it does not slow shell startup.
(Do *not* add the dir to `fpath` and re-run `compinit`; that re-audits every
completion dir on every new shell and is the usual cause of slow zsh startup.)
You get:

```
vbflasher si<TAB>            -> silence
vbflasher silence <TAB>      -> BCM PCM PSCM ABS ... ALL 7DF   (from the registry)
vbflasher dtc B<TAB>         -> BCM
vbflasher flash <TAB>        -> *.vbf files
vbflasher flash --<TAB>      -> every flash flag
```

To just print the script (e.g. to a system-wide dir), drop `--install`:
`vbflasher completion bash > /etc/bash_completion.d/vbflasher`. **Regenerate**
after adding a subcommand, flag, or ECU by re-running the same command.

## GUI

```bash
vbflasher --gui                     # or: python3 vbflasher_gui.py  (needs PySide6; Arch/Manjaro: pyside6)
```

A desktop launcher is optional: `~/.local/share/applications/vbflasher.desktop`
with `Exec=$HOME/.local/bin/vbflasher --gui`.

The toolbar selects the **module** (registry, or a custom tx CAN id) and the
**interface**: `auto` maps each module by its bus (HS-CAN → / MS-CAN → combos,
default can0/can1); picking an interface (e.g. `can2` for a bench unit) forces
it for every operation. One bus job runs at a time; **Stop** cancels a polling
job or sends Ctrl-C to a running CLI job.

| tab | what it does | how |
|---|---|---|
| Modules | scan every registered module: present/silent, F111/F188/F110/F113/F124/VIN, best definition | in-process |
| Flash | add VBFs (header, part, CRC check), all `flash` options, dry-run plan → confirm → flash with progress; `info`/`verify` | CLI subprocess |
| Module data & config | identify the module, pick its definition; **Show** config (writable), diagnostic data (read-only: switches, lamps, battery, TPMS… decoded per bit with scaling) or all, filter by text, read shown/selected, **Live poll** selected DIDs; read all writable DIDs, edit fields (enum combos / numbers / ASCII / raw hex), write changed DIDs with session + SecurityAccess, read-back verify; load/save UCDS *Direct Configuration* XML | in-process |
| Central config (CCC) | read the 512-byte CCC from BCM/IPC (address from D12B, SBL + 35 upload), decode it with the CCF definition, edit (enum lists are editable: type any raw value; the Raw column and "Edit raw bytes…" (`F106:17 = 06` / `0x111 = 06`) edit values outside the IDS list; firmware-only values are added from `defs.CCC_EXTRA_ENUM`), checksum auto-fixed, write back (fresh backup → confirm → `memwrite --erase-len` → read-back compare); load/save UCDS *As-Built* XML or .bin | CLI subprocess |
| DIDs | raw read / write / poll (changes only, stop-on-value) with optional session/unlock | in-process |
| DTCs | read with descriptions, scan all modules, clear one / clear ALL (7DF) | in-process |
| Service | reset (one / ALL), routine, silence, memread/memwrite, SBL test, `ford_brutekey`, self-test | mixed |

Every config read is backed up automatically to `logs/backups/` (UCDS XML for
DIDs, `.bin` for the CCC) before anything is written.

**Picking a definition.** In order: the module's own Part II spec from
**F110** (exact FDRS MDX), then sibling specs of the same family (marked
*verify!*), then vehicle definitions for the chosen model / model year at that
CAN address (IDS ffdata/CCF synthesis, then IDS platform MDX), then any spec
at that address. Search
covers spec, model and acronym. Field positions show `B<byte>.<bit>`
(byte 0 first, bit 7 = MSB). IDS ffdata scaling is converted on build:
physical = (raw + offset) × resolution (e.g. BCM `402A` battery voltage
0.05 V/bit + 6 V); ffdata carries no unit names, so synth values show
without units. Ford MDX `security_level_N` is SecurityAccess
`27 (2N-1)`, so config writes that publish level 2 unlock with `27 03`.

**The definition DB** (`defs/vbflasher_defs.sqlite`, ~15 MB, committed) is one
source-agnostic format built from IDSdb: 685 FDRS spec documents, ~10.6 k
model/MY/module documents, 50 CCF central-config layouts, DTC text per module
address. UCDS RAM extractions are merged into the same definitions, not kept
apart: every C520/C520_EU IPC (0x720) and BCM (0x726) definition also carries
the UCDS IPC level-3 list (`IPC/RE/config/ipc_did_defs.json`) and the BCM DIDs
decoded from UCDS (`BCM/Research/docs/ucds`: `DE00` config, `40D7` battery
quiescent-current statistics, `414C` battery-voltage statistics, plus the
`bcm_direct_config.json` catalogue: 498 named DIDs, 63 of them writable — the
UCDS *Direct Configuration* settings: `DE00`–`DE05`, remote start `EEAB`…`EEFD`,
`4227`, battery management, `4130`/`4155` lock/body options, TPMS sensor IDs,
vehicle mode `D134`; written with `10 03` + `27 03` like UCDS writes `DE00`;
PATS/immobiliser, identification and counters stay read-only), and every C520 IPMA (0x706) definition carries `DE00`–`DE03`
(Vehicle Parameters incl. Speed Unit KPH/MPH, Vehicle Parameters 2 = feature
default modes, Feature Options, DTC Mask) from `IPMA/Research/ucds`. Config
DIDs that are refused on a plain read are retried once in their write session
with the published SecurityAccess level (the IPMA needs `10 03` + `27 03` even
to read). A UCDS layout with fields replaces the IDS layout of the same DID; the
IDS session/security for that DID is kept (for the BCM catalogue its access class
wins). Layouts and DID sets are content-deduplicated; part-number lists and
security bytes are not copied. Rebuild after IDSdb changes:

```bash
python3 tools/build_defs.py         # ~10 s
```

**CCC facts used** (verified on three UCDS As-Built files): 512 bytes =
CCF blocks 1..5 (88+40+128+2+254); byte 256 = `0xFC` (block-5 length),
byte 257 = `sum(bytes 258..511) & 0xFF`. Erase length on write: BCM
DV6T/F1FT/F1DT `0x4000`, other BCM `0x400`, IPC `0x1000` (FoCCCus).

**Windows:** the GUI itself is portable, but the transport is Linux SocketCAN
with the kernel ISO-TP module. On Windows only the offline parts could work
(VBF info/verify, editing/decoding UCDS XML files — untested there); live bus
access would need a different transport backend (e.g. python-can + a
J2534/ELM adapter).

## Usage

```bash
vbflasher --selftest                      # offline self-tests
vbflasher --gui                           # graphical interface (see GUI)
vbflasher list                            # registered ECUs
vbflasher info   FILE.vbf [...]           # header + block table + integrity
vbflasher verify FILE.vbf [...]           # CRC check only
vbflasher ident  BCM                      # read a live module's IDs (name or id)
vbflasher ident  ALL                      # iterate every module, print each ident
vbflasher readdid BCM F190                # read one DID (hex + sanitized ascii)
vbflasher readdid PCM F111 F18C DE00      # several DIDs; binary-safe output
vbflasher readdid IPMA 41BB --poll 1 --changes      # watch a DID: one timestamped line per change
vbflasher readdid IPMA 41BB --poll 1 --until 0205   # ...and stop when it reads 02 05
vbflasher writedid BCM DE01 01A0FF        # write a DID (2E) from hex (asks y/N)
vbflasher writedid PCM F1AB 0011 --session 0x03 --unlock  # some DIDs need session+auth

# RoutineControl (31) — several ids run in order, --wait s apart, TesterPresent kept up
# (ready-made module procedures: see "Service procedures" below)
vbflasher routine ABS 0E08 0E06 --session 0x03 --sec-level 3   # ABS CCC learn (asks y/N)

# DTCs — no VBF needed; select ECU by name or CAN id
vbflasher dtc      BCM                     # actual faults only (default)
vbflasher dtc      ALL                     # per-module actual-DTC count overview
vbflasher dtc      BCM --all               # include 'not completed' entries
vbflasher dtc      7E0                     # by CAN id (PCM)
vbflasher dtc      PCM --status-mask 0x08  # only confirmed DTCs
vbflasher cleardtc BCM                     # clear one module (asks y/N)
vbflasher cleardtc 0x730 --yes             # clear, no prompt

# reset a module (11 01 hardReset by default)
vbflasher reset    BCM                     # hard reset one module
vbflasher reset    PCM --mode 0x03         # soft reset

# silence a module (hold in programmingSession so it stops transmitting)
vbflasher silence  BCM                     # quiet one module until Ctrl-C
vbflasher silence  PCM --duration 30       # quiet for 30 s then restore
vbflasher silence  ALL                     # quiet every module (functional 0x7DF)

# ALL modules at once, via functional 0x7DF broadcast (unconfirmed)
vbflasher cleardtc ALL --yes               # clear DTCs on every module
vbflasher reset    ALL --yes               # reboot every module
vbflasher reset    7DF --yes               # same (id form of ALL)

# dry run prints the full plan and connects to nothing
vbflasher flash  APP.vbf --dry-run
vbflasher flash  APP.vbf                   # live; asks "are you sure? [y/N]"
vbflasher flash  APP.vbf CAL.vbf           # several files in one session
vbflasher flash  APP.vbf --yes             # skip the prompt (scripting)
vbflasher flash  APP.vbf --test-sbl        # load+run SBL only, no erase/write
vbflasher flash  GWM --test-sbl --sbl /path/to/SBL.vbf  # same, no application VBF
vbflasher flash  APIM --test-sbl --skip-security --sbl sbl/X.vbf  # no 27 seed/key at all
vbflasher flash  APP.vbf --recovery --hw <F111>   # catch a PBL after power-up (see Flow)

# raw memory / EEPROM read & write (loads the SBL first, then 35 / 34+FF00)
# PSCM EEPROM lives at 0x02000000, 1024 bytes (see PSCM_ucds_eeprom_procedure.md)
vbflasher memread  PSCM --addr 0x02000000 --length 0x400 -o pscm_eeprom.bin
vbflasher memwrite PSCM --addr 0x02000000 -i pscm_eeprom.bin   # erase+write+verify+reset
```

By default you give only VBF file(s): the ECU is read from each file's
`ecu_address`, and the SBL + secret come from the internal database keyed on the
live F111. The registry also selects the physical CAN interface automatically:
HS-CAN modules use `can0`, while MS-CAN modules use `can1`. Commands targeting
`ALL` use both interfaces. Pass `--iface IFACE` to override this selection (and
to force `ALL` onto only that interface). The SBL VBF is looked up in the `sbl/`
subdir (then beside the flasher); if it is missing the tool tells you exactly
which file to supply.

Key flags: `--iface IFACE` (override the automatic bus interface),
`--dry-run/-n` (plan only, opens no socket), `--yes/-y` (skip the confirmation
prompt), `--sbl PATH` (override the auto-selected SBL), `--sbl-dir DIR` (extra
search dir, repeatable), `--secret 0x...` (override the seed-key secret),
`--sec-level N` (diag security level;
secrets can differ per level), `--skip-security` (programming session without
`27` seed/key — only for modules that allow it; no secret needed), `--hw STRING`
(assume an F111 for dry-run planning / recovery), `--test-sbl`, `--recovery`,
`--flood-interval`, `--catch-probe`, `--quiet-bus`, `--decompress`,
`--skip-blank`, `--blank-byte`, `--force`, `--rxid`, `--seed-delay`,
`--erase-timeout`, `--wake-tries`, `--wake-timeout`, `--progress-interval`,
`--tp-interval`, `--tp-id`, `--logfile`. `vbflasher <cmd> -h` is authoritative.

Every live run writes its own trace log — `logs/<YYYYMMDD>-<HHMMSS>_<ECU>_<cmd>.log`
(e.g. `logs/20260704-153012_BCM_flash.log`) — so logs never pile into one huge
file. `--logfile PATH` pins an explicit path (appended); `--logfile ''` disables
logging entirely.

### `--decompress` — transmit a compressed payload in plain

A VBF with `data_format_identifier = 0x10` carries LZSS-packed blocks. The
default (and the OEM/UCDS-proven) path sends those bytes **verbatim**:
`34 10 44 <addr> <compressed-len>`, and the ECU's boot loader unpacks them
internally. `--decompress` instead expands the payload on the host and sends it
plain — `34 00 44 <addr> <unpacked-len>` — for a boot loader that does not
implement format 0x10. The unpacked bytes are exactly the ones the block
CRC-16 covers, so integrity is still verified either way; the erase map and
load addresses are unchanged, only the transferred length grows (e.g. the IPC
`GJ5T-14C026-DL`: 3.4 MiB on the wire by default, 16.0 MiB with
`--decompress`). For a raw (`0x00` / absent dfi) container the flag is a no-op.
Prefer the default: sending expanded bytes to an ECU that expects compressed
ones — or the reverse — bricks the module.

### `--skip-blank [BYTES]` — don't transmit erased-blank padding

Many parts are mostly padding. `HM5T-14C088-BB` (C-MAX hybrid IPC) unpacks to
31.9 MiB of which **45% is 0xFF**, with single runs of 10.8 MiB and 1.4 MiB.
An erased NOR cell already reads 0xFF, so writing that padding is a no-op that
still costs wire time. `--skip-blank` splits the block around those runs and
sends only the non-blank spans — several `34`/`36…`/`37` downloads instead of
one:

    --decompress                   1 block,  31.9 MiB
    --decompress --skip-blank      4 blocks, 19.4 MiB   (39% less)

BYTES is the minimum run length to skip, default `4096` when the flag is given
bare. Only erased `0xFF` gaps are safe to omit. `--blank-byte` values other
than `0xFF` are refused: reassembly over a different fill could look correct
while the actual erased flash still contains `0xFF`.

**On a compressed (dfi 0x10) part it stays compressed.** The payload is
expanded host-side, split around the blank runs, and each fragment is then
**re-packed with the project's own LZSS encoder**, so the wire format is still
`34 10 44 <addr> <compressed-len>` and the ECU decompresses as usual — the
expanded image is only ever a host-side intermediate:

    default (send file as-is)        8.74 MiB on the wire
    --skip-blank                     7.76 MiB   (11% less, still dfi 0x10)
    --decompress --skip-blank       19.40 MiB   (plain, for a BL that can't unpack)

The 11% is close to the measured ceiling: the 0xFF runs occupy 15.8% of that
file's compressed stream, and an instrumented token map shows our encoder needs
**1.00x** Ford's bits on the identical byte range, so almost nothing is lost in
the re-pack. (Ford's headline 21% ratio vs our 48% on a whole block is a
*content* difference — their stream includes the trivially-compressible padding
we removed — not an encoder weakness.)

Four safety rules, all enforced, not assumed:

1. **A gap is only dropped if the part's own `erase` map covers it.** Outside an
   erase region the pre-existing flash content is unknown, so 0xFF is a value
   that must really be written. A region protected by `omit` does not count as
   erased either. With no `erase` header, nothing is skipped.
2. **Fragment bounds are aligned outward to 0x100**, so a download never starts
   or ends mid-word/mid-page; the kept span only ever grows.
3. **The split must be provably lossless.** Before anything is transmitted the
   fragments are reassembled over a 0xFF canvas and compared byte-for-byte with
   the full payload; any difference aborts the flash. (Verified to catch the
   failure: dropping 64 real bytes mid-fragment is reported as
   `reassembly differs … would leave a hole in flash`.)
4. **Re-packed fragments are decoded back before use**, through the same
   decoder the ECU implements, and the reassembly check runs on those decoded
   bytes. A re-pack that does not round-trip aborts the flash rather than
   reaching a module.

`lzss_encode()` output is *not* bit-identical to Ford's packer and does not need
to be — the ECU only has to decode it. Never use it to rebuild a `.vbf` whose
stored CRCs must stay valid: those cover the decompressed bytes (preserved), but
the container's block length would change.

## Flow

1. Parse **and fully verify** every VBF (block CRC-16 + file CRC-32) before any
   byte reaches the ECU. A mismatch aborts the flash; `--force` downgrades it
   to a warning (for a deliberately patched file whose CRCs were not
   recomputed). Files are grouped by `ecu_address` into sessions.
2. Connect, read **F111** and the other identity DIDs (printed as "current
   firmware").
3. From F111: pick the SBL VBF and the secret from `ecu_db`. Missing SBL ⇒ stop
   with instructions. `--sbl`/`--secret` override.
4. Print the **plan**: SBL, what is erased, what is written, current firmware
   IDs. Ask **"Are you sure? [y/N]"** (skip with `--yes`).
5. On `y`: `10 02` → `27 01/02` (seed-key; omitted with `--skip-security`) →
   download+start SBL → per region `31 01 FF00` erase → `34/36/37` download
   (each `37` CRC-16 echo is checked against the file) → profile-required
   `31 01 0304` finalise → `11 01` reset. `--test-sbl` stops right after the
   SBL starts.

For a DM5T IPC held in PBL after an incomplete programming sequence, wait for
any other flash session to finish and use a known-good, original MCU VBF:

```bash
vbflasher flash HM5T-14C026-BC.VBF --iface can1 \
    --hw DM5T-14F094-AB --recovery
```

`--recovery` waits for the PBL instead of probing live identity first; the
selected F111 (`--hw`) determines the SBL and level-1 secret. Without `--hw`,
give `--sbl` plus `--secret` (or `--skip-security`). `--recovery` forces
`--quiet-bus` on. This still erases and
rewrites MCU application flash and asks for confirmation. Check for finalise
reply `71 01 03 04 10 02` before reset; otherwise stop rather than repeat
flashes. OEM VBFs are supplied by the operator, not stored in this repository.

### How the PBL is caught

The catch is FORScan's, reproduced from the ABS captures
(`ford/ABS/forscan_recovery2.log`): a **continuous functional programmingSession
flood** — `7DF#02 10 82`, i.e. session 0x02 with the suppressPositiveResponse
bit, every 12 ms — that never waits for a reply. Two reasons it works where a
request/response loop fails:

* it cannot miss the few-millisecond window after power-up, because nothing
  blocks on a response (~83 requests/second instead of a handful);
* it holds every other module in programmingSession, so **the bus goes quiet**.
  A busy bus is the main reason the window is missed, which is why `--recovery`
  now forces `--quiet-bus` instead of forbidding it.

While the flood runs, the target is probed on its physical ISO-TP socket:
`22 D100` (`62 D1 00 02` = bootloader, `01` = application — FORScan's own
oracle) and a short `10 02`. Either a `D100 == 02` or any `50 02` ends the
catch; a negative response or silence on D100 proves nothing and never stops
it. After the catch the normal flow resumes: physical `10 02`, seed/key, SBL to
RAM, erase, download, finalise, reset — with its usual checks.

Tunables: `--flood-interval` (default 0.012 s, 0 disables the flood and probes
only) and `--catch-probe` (pause between probe rounds, default 0.05 s).

### Files that keep module data (retained-data gate)

Some profiles list `retained_regions`: module-owned data that the OEM file's
erase map wipes (CCM: Emulation Flash `0xFF8000` = alignment/configuration,
calibration banks `0xFFC800`). A VBF whose header `erase` list leaves one of them
standing (e.g. `CCM/RE/work/qa45/*-apponly.VBF`, `*-keepEEE.VBF`) keeps that data,
and the data is only coherent with the version that wrote it. The plan prints
`KEEPS 0x… <region>`, and the flash **refuses unless the ECU already reports the
same part number** (`F188 == sw_part_number`). `--force` downgrades it to a warning.
For a version change, flash the file with the full OEM erase map.

### CCM (Delphi ESR, 0x764)

Everything is reproduced from the UCDS captures (`ford/CCM/GV6T/`) and covered
offline by `.tests/test_ccm_flash_replay.py`, a fake bootloader that answers like
the capture and enforces erase-before-write. Security level 1 secret
`AACCCC3355` (capture-verified), SBL `AE9T-14D051-AA` to `0x03FF9000`, 128-byte
transfers, every `36` pending ~185 ms (≈0.7 KiB/s: about 9 min for the 352 KiB
application), `37` CRC echo, finalise `71 01 0304 10 02`.

```bash
vbflasher ident CCM                                        # F188 must match the file
vbflasher flash --dry-run GV6T-14D049-AD-qa45-apponly.VBF  # plan + KEEPS lines
vbflasher flash GV6T-14D049-AD-qa45-apponly.VBF
```

Not yet done live with VBFlasher. UCDS put the whole bus in programming first
(`7DF 10 82` ×71) and then sent the physical `10 02`. Whether the CCM application
also accepts a bare physical `10 02` is not captured. If it answers with a
negative response, rerun with `--quiet-bus`, which sends the same functional `10 82`.

## Service procedures

Post-repair / configuration procedures, reproduced with the generic `routine`
command plus `cleardtc` / `reset`. Each one is taken from a capture of a vendor
tool (UCDS) on this vehicle; the routine ids are **per module and per part
number** — do not reuse them on another variant. A positive `71` only means the
routine was *accepted*; the trailing status byte(s) are the module's verdict.
Every command asks `y/N` unless `--yes` is given.

### ABS — central car configuration (CCC) learn

Ford/Teves ATE MK61 (`CV61-14C036`, tx `0x760` / rx `0x768`, HS-CAN). Source:
`../ABS/ucds_abs_reset_CCC.log`; routine map in
`../ABS/ABS_MK61_target_identification.md` §4e. Run it after changing the CCC /
As-Built (e.g. the cruise-control byte) so the ABS re-learns the `0x40A`
broadcast.

```bash
vbflasher routine ABS 0E08 0E06 --session 0x03 --sec-level 3 --wait 15 --tp-id 0x7DF
vbflasher cleardtc ABS --yes          # the capture clears DTCs afterwards
vbflasher dtc ABS                     # expect no U2300
```

| step | bytes | expected |
|---|---|---|
| extended session | `10 03` | `50 03 00 32 01 F4` |
| SecurityAccess **level 3** | `27 03` / `27 04 <key>` | `67 04` |
| full learn (steps 1+2+3) | `31 01 0E08` | `71 01 0E08 10` |
| 15 s gap, `3E 80` on `7DF` | — | — |
| DTC re-evaluation (step 2) | `31 01 0E06` | `71 01 0E06 10` |

Level 3 uses the ABS secret `B83F247FFF` from `ecu_db.py`; the level-1
flashing secret (`42434D5932`) is rejected. To re-run only the DTC
re-evaluation: `vbflasher routine ABS 0E06 --session 0x03 --sec-level 3`.

### HCM — headlamp levelling learn and actuator tests

HCM `7S71-13K031-CC` (tx `0x734` / rx `0x73C`, HS-CAN). Source:
`../HCM/hscan_learn_level.log`, `hscan_test_up.log`, `hscan_test_down.log`;
full analysis in `../HCM/HCM_PROCEDURES.md`. Extended session only — **no
SecurityAccess**: do not add `--unlock`, `--sec-level` or `--data`.

```bash
# level learn — the captured sequence: clear DTCs, learn, reset, clear DTCs
vbflasher cleardtc HCM --yes
vbflasher routine  HCM 200D --session 0x03 --tp-id 0x7DF
vbflasher reset    HCM --yes          # 11 01, ~1.2 s after the learn in the capture
vbflasher cleardtc HCM --yes

# actuator tests — move the headlamp levelling motors
vbflasher routine  HCM 2017 --session 0x03    # up
vbflasher routine  HCM 2018 --session 0x03    # down
```

| operation | request | captured response |
|---|---|---|
| level learn | `31 01 200D` | `71 01 200D 00 00` |
| up test | `31 01 2017` | `71 01 2017 00 00` |
| down test | `31 01 2018` | `71 01 2018 00 00` |

Before the learn, put the vehicle in the levelling condition (unladen, level
floor, settled); the capture does not encode it. Check the height sensors
before and after with `vbflasher readdid HCM 3B03 3B05` (front / rear, raw
`uint16_be − 200` = mm). The IDS sensor-height procedure uses a different
routine (`0x2054`) for other platforms — it is **not** this module's learn.

#### HCM flashing / SBL (V850 Visteon generation)

Bench-proven on `7S71-13K031-CC`, F188 `AM51-14C084-CB`, F120 `AM51-14C399-AB`
(`vbflasher flash HCM --test-sbl`, 6 runs on 2026-11-14: 5 started the SBL, the first one hung, see below).

* **F111 is refused (NRC 31)**, so the SBL and secret are picked from the software
  part: `AM51-14C084*`/`7S71-14C084*` → SBL `AM51-14C087-AA` (same payload as
  `7S71-14C087-AB`, call `0xFFFFE254`), level-1 secret `DACCCB6EB3` (IDS ffdata HCM
  VMC_9938 C520_EU; accepted by both the application and the PBL).
* **Unlock the application in `10 03` BEFORE `10 02`.** Otherwise `27 01` in the
  programming session answers `7F 27 7F`. The profile does this automatically
  (`prog_preunlock_session=0x03`): `10 03` → `27 01/02` → `10 02` → `27 01/02` (the PBL
  seed is a constant `03 76 A5`) → `34/36/37` ×4 (each `37` echoes the block CRC-16) →
  `31 01 0301 FFFFE254` → `71 01 03 01 00 00`.
* The SBL's service table (block at `0xFFFFEED0`) holds `10 11 3E 22 27 36 37 31 34 2E`.
  It has **no `35` RequestUpload**, and the application answers `23` with NRC 11.
  There is no read-back or backup path, so `memread`/`backup` cannot work on this module.
* **One unexplained hang:** the first SBL start of the session got no response to
  `31 01 0301` for 10 s. The tool aborted before any erase, and the module was back in its
  application when probed later. Five later starts succeeded, including one directly after
  a seed-only `10 02` visit. A cold-boot RAM dependency is unconfirmed: power-cycle the
  module, then run `--test-sbl` first. If that start hangs, it reproduces the failure.
  A start that times out never erases, so the failure is safe.
* **DID definitions** for the GUI's module-data view come from the application's own
  DID table (flash `0x870`, 33 DIDs + D100), not from IDS. IDS lists DIDs this module
  answers with NRC 31 (DD0x, 7211, E734, ...). Source: `../HCM/hcm_did_defs.json`, built
  into the defs DB by `tools/build_defs.py` as spec `DS7S71-13K031-CA` (matched on F110).
  Decoded fields include the stored CCC parameters (F106), CCC faults (E103), heights,
  ADC values, learned zeros and the leveling target and actuator command.
* GEN3 Varroc HCM (`AM51-14C084-DA`, `GJ5T-14D063`, F111 `AM51-14F110`): SBL
  `BK21-14D065-AA` and secret `08306155AA` come from IDS. **Not tested on a module.**

### IPMA — front camera alignment learn (drive)

F1FT IPMA (tx `0x706` / rx `0x70E`, HS-CAN). Source: IDS capture
`../IPMA/Research/ids_ipma_calib.log`; routine and DID analysis in
`../IPMA/Research/IPMA_camera_alignment.md` §7. Needs extended session +
SecurityAccess **level 3** (secret `0000E727FB`; the level-1 flashing secret
does not work). Run it after the camera or windscreen bracket was moved or
replaced. Proven once on this car: complete after ~6.5 min of driving on
marked roads.

**1. Measure the wheel-arch heights** (FL, FR, RL, RR, in mm, at the points
the Ford procedure specifies, car standing level). They are the body
attitude reference: an error here becomes the same error in learned pitch.
Encode each as a big-endian u16 (hex), in that order:

    790, 790, 810, 810  ->  0316 0316 032A 032A  ->  --data 03160316032A032A

**2. Check it is idle, then start the learn — exactly once:**

```bash
vbflasher readdid IPMA 41BB 41BA                  # 41BB must be 00 xx (idle)
vbflasher routine IPMA 2050 --data 03160316032A032A --session 0x03 --sec-level 3
```

Expect `71 01 2050 10`. Routine `2050` is a **toggle**: sending it while an
alignment is running *aborts* it (that is also the only way to cancel:
the same command, the height bytes are ignored on the clearing call). Never
re-send it "to make sure"; check `41BB` instead. The heights live in RAM until
the learn completes — a power cycle mid-drive loses the run.

**3. Drive, and watch it progress** — start the watch right away; it holds the
extended session and level-3 security with TesterPresent, the way IDS does,
and re-unlocks automatically if the context is lost:

```bash
vbflasher readdid IPMA 41BB FD05 --poll 1 --changes --until 0205 \
    --session 0x03 --sec-level 3
```

`41BB` (Camera Alignment Status), 2 bytes:

| byte 0 — state | byte 1 — progress |
|---|---|
| `00` idle / not aligning | `00` <20 % |
| `01` **running** | `01` 20–39 % |
| `02` **complete** | `02` 40–59 % |
| `03` unobserved (failure/abort suspected) | `03` 60–79 %, `04` 80–99 %, `05` ≥100 % |

The proven run: `00 00` → `01 00` once the car moved (6 s) → `01 01` at 140 s →
`01 02` 263 s → `01 03` 307 s → `01 04` 345 s → **`02 05` at 393 s**. Progress
depends on lane-marking quality, not distance. `--until 0205` ends the watch
at completion; drop `FD05` (and the session/security flags) to watch `41BB`
alone without unlocking.

**4. Verify it committed:**

```bash
vbflasher readdid IPMA 41BA                                  # = the heights you sent
vbflasher readdid IPMA FD05 --session 0x03 --sec-level 3     # learned angles
```

`41BA` changes to the heights you entered only when the result is written to
NVM — the independent proof of commit. `FD05` (20 bytes: pitch / roll / yaw
float32 BE degrees, then Z / Y / X int16 mm, pad, quality) gets new angles and
its last byte goes `FF` → `00`; the X/Y/Z mount offsets are left untouched.
Decoded output, an automatic "already running" guard and CSV/JSON logging are
in `../IPMA/Research/work/ipma_align.py run --heights 790,790,810,810`.

### HVAC (DEATC 0x733) — flashing

Two hardware generations answer on 0x733 (MS-CAN, `can1`):

| generation | software (F188) | SBL | secret level 1 / 3 | evidence |
|---|---|---|---|---|
| paged (older) | `CJ5T-18D619-*`, F111 `AM5T-14C239-*` | `AM5T-18D618-BB` | `415249414E` (any level) | SBL from FoCCCus; the secret is an **unverified** registry guess (FoCCCus has no 0x733 secret) |
| Visteon V850E2/Fx4-L | `GJ5T-18D619-*` | `F1ET-18D618-AA` (V850 Fx4-L flash driver, RAM 0xFEDF8000) | `AFFE55EFFA` / `C346C346AA` | secrets read from the GJ5T application's SecurityAccess table (0xADE8 in AK); its keygen is the standard Ford LFSR (`test_hvac_profile`). SBL family match, not capture-proven |

The V850 module's F111 lives in an EOL-written flash page and is not known, so this generation is chosen
by the **software** part: the live F188 when it can be read, otherwise the part number of the VBF
(dry run, `--recovery`). A VBF whose software part selects a different generation from the live F188
(e.g. a GJ5T image on a CJ5T module — both are family `18D619`) is refused unless `--force`.

```bash
vbflasher flash GJ5T-18D619-AK_seatheat.vbf --dry-run      # plan: F1ET SBL, AFFE55EFFA
vbflasher flash GJ5T-18D619-AK_seatheat.vbf                # live (asks before erase)
vbflasher flash GJ5T-18D619-AK.vbf --recovery              # stock image back, PBL catch
```

Not yet proven on a module: the PBL accepting the application's level-1 secret, the F1ET SBL on GJ5T
hardware, and the `31 01 0304` finalise answer (no response gate is set). The first live run is the
test — keep the stock `GJ5T-18D619-AK.vbf` at hand. The patched HVAC image and its internal checksums are
described in `../HVAC/docs/HVAC_GJ5T_firmware_reference.md`.

## Raw memory / EEPROM read & write

`memread` / `memwrite` reuse the exact proven preamble (session → security →
SBL load+start) and then operate on an **arbitrary address range** instead of a
VBF's block table — the same UDS services the OEM UCDS tool used to read/write
the PSCM EEPROM (reconstructed in
`PSCM/Research/PSCM_ucds_eeprom_procedure.md`):

* **memread** = `35 RequestUpload <addr><len>` → `36` (read) × N → `37`, then
  saves the bytes to a file and prints their SHA-256. Non-destructive; ECUReset
  afterwards unless `--no-reset`.
* **memwrite** = `31 01 FF00` erase → `34 RequestDownload` → `36` × N → `37` →
  `31 01 0304` verify → `11 01` reset. Skips can be toggled with `--no-erase` /
  `--no-verify`. Prompts `y/N` (bypass `--yes`).

The ECU declares its own `maxNumberOfBlockLength` in the `0x75`/`0x74` response,
so the chunk size is never hardcoded. Select the ECU by name or CAN id; the SBL
and secret come from F111 exactly as `flash` does (`--sbl`/`--secret`/`--hw`
override). `--addr-len-fmt` (default `0x44` = 4-byte addr + 4-byte len) covers
the addressAndLengthFormatId if a module needs a different one.

```bash
# back up then restore the PSCM EEPROM (0x02000000, 1024 bytes)
vbflasher memread  PSCM --addr 0x02000000 --length 0x400 -o pscm_eeprom.bin
vbflasher memwrite PSCM --addr 0x02000000 -i pscm_eeprom.bin
```

### Full-module backup (`backup`)

`backup <ECU>` reads every region of the profile's `backup_regions` map for the
live F111 into one directory plus a `manifest.json` (ident DIDs, per-region
address/length/SHA-256/CRC-32). Read-only: it sends no erase routine and no
`2E`, and the only `34` is the one that loads the SBL into RAM. Regions marked
`via="rmba"` are read first by the APPLICATION with `23 24 <addr32> <len16>`
(session `rmba_session`, level `rmba_level`). Regions it refuses, such as the
primary bootloader, the SBL cannot reach either. The rest go through the SBL in
`--segment` transactions (default 64 KiB). Each segment is checked against
the CRC-16 that the `37` echoes and is re-read on a mismatch. If the echo is
evidently not a CRC (two identical reads, echo still different), the segment is
kept and counted as unchecked in the manifest. A partial file stays `*.part`.
A region marked `blank_noise` (RH850 data flash: erased cells read back random,
so neither the echo nor a re-read can agree) is read `votes` times instead. The
per-byte majority is stored, plus a `<name>.unstable` mask (1 = the reads
disagreed). Re-running with `--only <names>` into the same `-o` directory
resumes: the earlier regions are kept in the manifest, and a different module
(F111/F18C/software mismatch) is refused.

```bash
vbflasher backup IPMA --iface can3 -o backups/ipma_213502402      # ~85 min, CGEA IPMA
vbflasher backup IPMA --only pbl,rh850_app,rh850_cal,rh850_dflash  # RH850 side only, ~9 min
```

**Back to VBF.** `tools/backup2vbf.py BACKUP_DIR OEM.vbf ... -o OUT` rebuilds
flashable VBFs from the backup, with the OEM file as the template (header kept
verbatim except `file_checksum`). It refuses a template whose part number the
module did not report, bytes the backup lacks, and blank-noise bytes.
`--layout oem` keeps the OEM blocks; for the part the module runs, it must
reproduce the OEM file byte-for-byte. `--layout erase` adds one block per
non-blank span of the erase map that no OEM block covers, i.e. the module data
that an OEM flash would erase and not restore.

Upload speed is set by the module: the CGEA IPMA sends its ConsecutiveFrames
every 1.0 ms even with FC STmin=0, so it runs at ~6.8 KiB/s (SBL download, by
contrast, runs at ~28 KiB/s).

### CGEA IPMA (JX7T-14F403, Focus mk4 / Fiesta MCA camera)

Same diagnostic address as the older F1FT/CV4T IPMA (0x706/0x70E) but a
different security scheme. Rules keyed on F111 `JX7T-14F403` select it, and the
F1FT generation keeps its LFSR secrets:

| level | where | keygen (`cgea_seckey.py`) | status |
|---|---|---|---|
| 1 | PBL, `10 02` | `HMAC-SHA1("DELPHIIPMA01", seed16 + "JaKe")[0:18]` | live-verified |
| 3 | application, `10 03` | `HMAC-SHA1("30AMPIIHPLED", "zaCK" + seed16)[4:20]` | 3 UCDS pairs + live |

SBL `H1BT-14F399-AB` (RAM `0xFEBD0000`) starts with `71 01 0301 10`. It serves
`35 RequestUpload` for RH850 code flash `0x00010000-0x00300000`, data flash
`0xFF200000-0xFF210000` and the whole 32 MiB EyeQ3 flash `0xB0000000-0xB2000000`.
The PBL (`0x0`, 64 KiB) and RAM give NRC 31. The PBL is read through the
application's `23` instead. Reading is proven: every region compared byte-exact
with the OEM file of the running part. Writing (erase/flash) of this
generation has NOT been exercised yet.

```bash
vbflasher readdid IPMA DE00 --session 0x03 --sec-level 3 --iface can3   # app unlock, 16-byte key
vbflasher memread IPMA --addr 0xFF200000 --length 0x10000 -o dflash.bin --iface can3
```

### Reading the BCM car-configuration (CCC)

Reconstructed from a UCDS capture (`../BCM/Research/ucds_read_ccc.log`). The
whole session runs in the **default session after SecurityAccess level 1**
(the registry's DV6T/F1FT/F1DT secret, `16C0BF803D`) — no SBL, no programming
session. UCDS:

1. reads `22 D12B` → `00 00 80 00`: the address of the upload/result buffer;
2. `34/36/37`-downloads a ~13 KB helper applet to RAM `0x40002000` (len
   `0x339E`), then writes its parameter cells:
   `0x4000E3B8`=`40002A24`, `0x4000E400`= a name→addr table
   (`SBL1 0x4000E600`, `SBL2 0x4000E6D8`, `SBL3 0x00320000`, `SBL4 0x0FC00000`),
   `0x4000E480` (214 B) and `0x4000E600` (238 B) parameter blocks,
   `0x4000E6F0`=`000003E8`;
3. runs it with `31 01 0301 40002000` (RoutineControl start, arg = applet base);
4. `35`-uploads the result: **`0x00008000`, `0x200` (512) bytes** — the CCC /
   As-Built block (starts with the ASCII part/VIN strings). The applet marshals
   it there from config flash `0x00320000` / `0x0FC00000`.

vbflasher does **not** carry UCDS's RAM applet, so it can't reproduce step 3.
But you don't need it: after `memread` loads the Ford SBL and does the level-1
SecurityAccess, the CCC buffer at `0x00008000` is already populated, so a plain
`35 RequestUpload` of that region returns the same 512 bytes UCDS uploads:

```bash
# VERIFIED on the bench BCM: the 512-byte CCC / As-Built buffer (addr from D12B)
vbflasher memread BCM --addr 0x00008000 --length 0x200 -o bcm_ccc.bin
```

The underlying config-flash regions the applet marshals from
(`0x00320000`, `0x0FC00000`) are **out of range** for the SBL's `35` handler and
cannot be read this way — use the `0x00008000` buffer above.

**Writing the CCC back** needs a larger erase than the data. The ECU's
`31 01 FF00` erases whole flash **sectors** and rejects a short length with
`requestOutOfRange` (`7F 31 31`), so erasing only `0x200` fails even though you
write `0x200`. Pass `--erase-len` with the per-ECU sector size (from FoCCCus
`ford_c346.cpp::writeCccToEcu`):

| ECU | F111 prefix | erase length |
|-----|-------------|--------------|
| BCM | DV6T / F1FT / F1DT | `0x4000` |
| BCM | BV6N (and other)   | `0x400`  |
| IPC | —                  | `0x1000` |

```bash
# write the 512-byte CCC back to a DV6T/F1FT/F1DT BCM (erase a full 0x4000 sector)
vbflasher memwrite BCM --addr 0x00008000 -i bcm_ccc.bin --erase-len 0x4000
```

`--erase-len` only affects the `31 01 FF00` erase span; the download still writes
exactly the file size. Take a `memread` backup first.


Safety: a plan is always printed and gated behind a `y/N` prompt (`--dry-run`
opts out and opens no socket; `--yes` skips the prompt for scripting); DLC=8
padding (Ford ignores short frames); `0x78`
responsePending treated as CONTINUE with a clock that restarts on each pending;
EXE parts gated on F188==VBF part (DATA/calibration reported only); `--quiet-bus`
is opt-in for normal flashes and forced on by `--recovery`.

## Finding an unknown secret

When `ecu_db` has no secret for a module, `ford_brutekey.py` tries 381
candidates: the 343 FoCCCus ships (`KEYBAG`, from `c346::bruteSecretKey()`)
plus 38 harvested from other public Ford tools (`KEYBAG_EXT` — jakka351's
`FG-Falcon` per-module `.key` XML files and `FG1.py` table, and the
`Ford-ECU-Bruteforcer` C# keybag / ForScan word list). `--no-ext` restricts the
run to the FoCCCus set.

```bash
ford_brutekey.py IPC --iface can1 --level 1 --dry-run   # plan, opens no socket
ford_brutekey.py IPC --iface can1 --level 1 --yes       # live run
ford_brutekey.py IPC --iface can1 --level 3 --only 000024E4DE --yes  # test one
ford_brutekey.py --self-test                            # offline proof, no bus
```

It sends **only** `10 xx`, `27 <level>/<level+1>`, `3E 00`, and `11 01
ECUReset` when the module locks out after its 2–3 allowed wrong keys — no
erase, no download, no DID write. The reset is a visible cluster reboot, so the
vehicle must be stationary. A hit is re-verified in a second session with a
fresh seed before it is reported, and an all-zero seed (level already unlocked,
every key accepted) is refused rather than reported as a find.

This is a **dictionary**, not a brute force. But the full keyspace is NOT 2^40:
the keygen is affine over GF(2), and the secret→key map has rank 24, so its
kernel is 16 bits. Every secret therefore belongs to a class of 2^16 = 65536
secrets that yield **identical keys for every seed**, and only **2^24 =
16,777,216** classes are distinguishable. Enumerating `c << 16` for
`c` in [0, 2^24) hits every class exactly once (verified: 4000 sampled
representatives gave 4000 distinct key signatures, zero collisions).

Measured on the C-MAX IPC: **166 tries/s** sustained (each try is `27 01` +
`27 02`, ~3 ms each, keygen only 43 µs = 0.7% of wall time; 1 stall per 20000).
That makes an exhaustive level-1 search **28 h worst case, 14 h expected** —
feasible, unlike 2^40 which would take 2.1 million years at the same rate.

Note that key guesses **cannot** be batched: only the first `27 02` after a
seed is evaluated, and every later one returns `NRC 24 requestSequenceError`,
so each try costs a fresh `27 01`.

A dictionary miss means "not in this dictionary" — prefer solving the secret
from a UCDS capture (the affine structure lets ONE seed/key pair pin the class
exactly by Gaussian elimination) over a 14-hour search.

Measured: the 381-candidate level-1 dictionary run against the **running
application** returned `NRC 35 invalidKey` for every candidate. That says
nothing about the PBL's separate security context. The DM5T PBL's level-1
secret `EC6D038211` has since been validated on the live module and is
registered in `ecu_db.py`; no key search is needed to flash this PBL.

The secret required for flashing resides in the PBL, not in the application
VBF: the application starts at `0x0000C000` and excludes the first 48 KB of
flash. A RAM dump of the running application found its level-3 secret at
`0x400086D3` (`01 02 03 04 05`), but not the PBL level-1 secret. Do not
confuse a level-3 unlock of the application with level-1 access to the PBL.

The PBL needs level 1 before it accepts a RAM SBL or any application download:

| session | level | `34` download | `23` read |
|---|---|---|---|
| `10 03` extended | 3 (known) | NRC 7F, refused | works — RAM only |
| `10 02` programming (PBL) | 1 (`EC6D038211`, live-validated) | works after unlock | NRC 11, not supported |

After transferring a stock HM5T MCU application, the DM5T PBL also requires
`31 01 0304` finalisation. Success is `71 01 03 04 10 02`: the PBL then writes
its boot-commit marker. A positive `0x71` alone is not sufficient, and a reset
without finalisation can leave the module in PBL despite a successful transfer.

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
    # non-LFSR keygen: SecretRule("HWPREFIX", 1, "<secret bytes hex>", algo="cgea_pbl")
    # full-module backup map: backup_regions=(BackupRegion("HWPREFIX", "app", 0x10000, 0x80000),)
    # F111 unknown? key a rule on the SOFTWARE part instead (live F188/F120...,
    # else the VBF being flashed):  SblRule("", "SBL.vbf", sw_prefix="GJ5T-18D619")
    # and SecretRule("", 1, "...", sw_prefix="GJ5T-18D619")
    default_sbl="MY-SBL.vbf",                      # fallback
    finalize=True,          # run 31 01 0304 before reset (PCM/TCM/ABS/PSCM/IPMA)
    # module data an OEM file's erase map wipes; a file that skips it needs the same version
    # retained_regions=((0xFF8000, 0x4000, "emulated EEPROM"),),
    sbl_call_halfword=False,# start SBL with high 16 bits only (no known ECU; default full 4-byte addr)
)
```

Registered today (`vbflasher list`): IPMA 0x706, GWM 0x716, IPC 0x720,
BCM 0x726, ACM 0x727, PSCM 0x730, DEATC/HVAC 0x733, HCM 0x734, RCM 0x737, ABS 0x760, CCM 0x764,
FCDIM 0x7A5, APIM 0x7D0, PCM 0x7E0, TCM 0x7E1.

After adding a module, extend the MS-CAN set in `--selftest` if it lives on
MS-CAN, add a `.tests/test_*.py` for anything capture-derived, and regenerate the
shell completion.

## Tests

Everything runs offline — CAN sockets, sleeps and the ECU are mocked. The unit
tests live in `.tests/`, which is git-ignored (local working copy only); each
file puts the repo root on `sys.path`, so discovery works from any directory:

```bash
python3 vbflasher.py --selftest                  # registry, keygen, parser, primitives
python3 -m unittest discover -s .tests           # capture regressions + CLI flows
```

| file | covers |
|---|---|
| `test_flash_cli.py` | flash planning/dry-run, family gate, `--skip-security`, `--skip-blank`, flash-order guard |
| `test_recovery.py` | `--recovery` PBL catch (`7DF 10 82` flood, `22 D100` / `10 02` probes) |
| `test_progress.py` | progress bar, speed/ETA, total-time report |
| `test_seed_delay.py` | settle before `requestSeed` |
| `test_routine.py` | `routine` (31 RoutineControl) |
| `test_readdid_poll.py` | `readdid --poll` (periodic watch, `--until`, `--changes`, session recovery) |
| `test_abs_capture.py` / `test_ccm_capture.py` | secrets, SBL/finalise signatures, `37` CRC echoes from FORScan / UCDS captures |
| `test_ccm_flash_replay.py` | full CCM flash against a fake ESR bootloader (pending `36`/`37`, erase-before-write); qa45 full/keepEEE/apponly; retained-data gate |
| `test_hcm_profile.py` | HCM registry, software-keyed SBL/secret selection, bench seed/key pairs, `10 03` pre-unlock order, firmware DID definitions in the defs DB (bench F106 decode), `readdid` |
| `test_hvac_profile.py` | HVAC generations, software-keyed SBL/secret, generation guard, keygen vs the GJ5T application (`../HVAC/work/AK.bin`, skips when absent) |

Tests that need OEM VBFs outside the repo (`../ABS/*.vbf`) skip when absent.

## Provenance

Secrets/SBLs: FoCCCus `ford_c346.cpp` (`getSecret`, `getSblFilename`, keyed on
F111). Hardware-relevant: BCM `16C0BF803D` (DV6T/F1FT/F1DT level 1; supersedes the
older `64000B0C59`), PSCM `00009B2533` (published, unverified on the module
— treat the first live `27 02` as the test), IPMA `00009875CA` (solved from two
captured sessions). ACM `50C86A49F1` for CV4T (`CV4T-14F188` F111): read
from the CV4T-14D099 application (keygen identical to `ford_seckey`), then
proven by a live flash of `CV4T-14D100-TE` with SBL `CV4T-14D101-AA`; the
FoCCCus ACM secret `13F129B301` is rejected by that module (NRC 35) and is kept
only for the BM5T generation.
