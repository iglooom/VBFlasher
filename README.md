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

## Usage

```bash
vbflasher --selftest                      # offline self-tests
vbflasher list                            # registered ECUs
vbflasher info   FILE.vbf [...]           # header + block table + integrity
vbflasher verify FILE.vbf [...]           # CRC check only
vbflasher ident  BCM                      # read a live module's IDs (name or id)
vbflasher ident  ALL                      # iterate every module, print each ident
vbflasher readdid BCM F190                # read one DID (hex + sanitized ascii)
vbflasher readdid PCM F111 F18C DE00      # several DIDs; binary-safe output
vbflasher writedid BCM DE01 01A0FF        # write a DID (2E) from hex (asks y/N)
vbflasher writedid PCM F1AB 0011 --session 0x03 --unlock  # some DIDs need session+auth

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

# raw memory / EEPROM read & write (loads the SBL first, then 35 / 34+FF00)
# PSCM EEPROM lives at 0x02000000, 1024 bytes (see PSCM_ucds_eeprom_procedure.md)
vbflasher memread  PSCM --addr 0x02000000 --length 0x400 -o pscm_eeprom.bin
vbflasher memwrite PSCM --addr 0x02000000 -i pscm_eeprom.bin   # erase+write+verify+reset
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

### Reading the BCM car-configuration (CCC)

Reconstructed from a UCDS capture (`../BCM/Research/ucds_read_ccc.log`). The
whole session runs in the **default session after SecurityAccess level 1**
(secret `64000B0C59`) — no SBL, no programming session. UCDS:

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
    sbl_call_halfword=False,# start SBL with high 16 bits only (no known ECU; default full 4-byte addr)
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
