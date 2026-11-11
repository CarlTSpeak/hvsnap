# hvsnap output format reference

Everything a consumer needs to parse a capture without reading source code.
Every format below is emitted by `hvctl snapshot`; examples are taken from a
real capture (with illustrative values where a section postdates the sample).

## 0. Ground rules

- **Format names keep the `hvtrace` prefix** (`hvtrace.json`,
  `slf.hvtrace.snapshot-ext.*`). The *tool* is hvsnap; the *format* was never
  renamed. Captures from hvsnap and pre-rename hvtrace builds are
  interchangeable.
- **Text files use LF** line endings; all values are ASCII hex **with** a
  `0x` prefix unless noted (XMM/YMM rows are bare hex digits).
- **Provenance is explicit.** Every measured fact names where it came from:
  `same_hit_guest` (captured in the hypervisor exit of the freeze itself —
  the values the target instruction would have observed), 
  `parked_thread_context` (suspended thread's Windows CONTEXT),
  `host_cpu_enumeration` (CPUID/xcr0 facts about the host CPU, not the
  frozen instruction), or `derived` (documented Win64 convention fallback).
- **Absent is reported, never zero-filled.** If a component could not be
  measured you get `status: "absent"` (JSON) or `*_provenance=absent`
  (regs.txt) with the value omitted or explicitly not-trusted — a zero you
  see is a measured/derived zero, not a placeholder.
- **Coherent point-in-time.** Every target thread is suspended before the
  dump; the whole directory is one consistent image. `snap_rip`/`rip` mark
  the frozen instruction.
- The format evolves **additively**: new rows/fields appear, existing ones
  keep their spelling. Parsers should tolerate unknown keys.

## 1. Directory layout

```
<out>\snapshot_full_<prefix>_<NNN>_rip<rip-hex>\
```

One directory per capture (`<NNN>` is `000`; one snapshot per run). Inside:

| File | Kind |
|---|---|
| `hvtrace.json` | provenance header (§2) |
| `<tag>_regs.txt` | register state (§3) |
| `<tag>_teb_<addr>_<size>.bin`, `<tag>_peb_<addr>_<size>.bin` | TEB (0x2000) / PEB (0x1000) raw dumps |
| `<tag>_stack_<addr>_<size>.bin` | full stack, TEB `StackLimit`→`StackBase` |
| `<tag>_tls_ptrarray_<addr>_<size>.bin` | TLS pointer array (first 0x800 bytes) |
| `<tag>_tls_block_<addr>_<size>.bin` | per-module TLS block, up to 0x10000 bytes each (walk stops after 4 consecutive invalid entries, 256 max) |
| `<tag>_tls_slots_<addr>_<size>.bin` | static TLS slots (TEB+0x1480, 0x200 bytes) |
| `region_<base>_<size>_<prot>_<type>.bin` | one raw dump per committed region (§5) |
| `manifest.txt` | the page walk (§6) |
| `snapshot.ext.json` | extended-state sidecar v2 (§7) |
| `snapshot.ext3.json` | extended-state sidecar v3 (§8; skippable via `--no-ext3`) |

`<tag>` = `<prefix>_<NNN>_rip<rip-hex>`. Addresses/sizes in filenames are
bare lower-case hex, no `0x` (e.g. `teb_25a000_2000.bin`).

## 2. `hvtrace.json`

```json
{
  "hvtrace_version": "1.0",
  "created_utc": "2026-11-04T18:02:58Z",
  "target": {
    "pid": 94116,
    "image": "C:\\...\\target.exe",
    "hit_tid": 95572
  },
  "freeze": {
    "rip": "0x1441a77c0",
    "module": "target.exe",
    "module_base": "0x140000000",
    "module_size": "0x1fdd4000",
    "module_offset": "0x41a77c0"
  },
  "snapshot": { "prefix": "dyndtor", "tag": "dyndtor_000_rip1441a77c0", "format": "pinscan_full" }
}
```

`freeze.module*` is resolved from the **target's own module list**, not the
CLI hint. Hex strings carry `0x`. `hit_tid` is the thread that hit the RIP.

## 3. `<tag>_regs.txt`

Header line `# pinscan snapshot register state`, then `key=0xvalue` rows in
this order (conditional rows noted):

```
snap_rip, tid
rax rbx rcx rdx rsi rdi rbp rsp r8..r15        # 16 GPRs (parked CONTEXT)
rip, rflags
seg_cs seg_ss seg_ds seg_es seg_fs seg_gs      # 16-bit selectors
fs_base, gs_base  (+ fs_base_provenance / gs_base_provenance:
                   "measured" from the VMCB at the hit, or "derived"
                   fallback = Win64 convention FS=0 / GS=TEB on old drivers)
mxcsr
cr0 cr2 cr3 cr4 efer                           # VMCB-measured (see below)
dr6_vmcb dr7_vmcb
star lstar cstar sfmask kernel_gs_base
sysenter_cs sysenter_esp sysenter_eip
cpl gpat dbgctl
tsc_guest tsc_aux cr8
extended_msrs_provenance=measured_vmcbsave | absent
tsc_provenance=guest_visible_at_park
cr8_provenance=exit_entry_latch
control_regs_provenance=measured | absent
dr0 dr1 dr2 dr3 dr6 dr7                        # thread CONTEXT debug regs
fctrl fstat ftag fop fip fcs fdp fds           # x87
st0..st7                                       # 16 bytes each, bare hex
xmm0..xmm15                                    # 32 hex chars, bare hex
```

Real excerpt:

```
snap_rip=0x1441a77c0
rax=0x1441a77c0
...
fs_base=0x0
gs_base=0x25a000
fs_base_provenance=measured
gs_base_provenance=measured
...
tsc_guest=0x18af362f854593
cr8_provenance=exit_entry_latch
xmm8=00000000000000000000000000000000
```

The `*_vmcb` / VMCB block rows are the **same-hit** values (what the frozen
instruction would have observed); the plain `dr0..dr7`, x87, XMM and GPR rows
are the **parked thread's CONTEXT**. When the driver predates a measurement
the corresponding `*_provenance=absent` row replaces the value rows.

## 4. OS-structure dumps (`.bin`)

Raw bytes read cross-process while frozen. TEB 0x2000, PEB 0x1000, full
stack, TLS arrays/blocks/slots per §1. These are ordinary memory images —
no header, no padding.

## 5. `region_*.bin` — whole committed address space

Filename grammar: `region_<base-hex>_<size-hex>_<prot>_<type>.bin`, e.g.
`region_1010000_50000_RW_PRV.bin`. Contents = the raw bytes of that committed
region at freeze time. Guard/`NOACCESS` pages are temporarily unlocked for
the read and re-protected afterwards (the bytes are real).

`<prot>` decodes the region's memory protection:

| Label | Meaning |
|---|---|
| `X` / `RX` / `RWX` | execute / read-execute / read-write-execute |
| `R` / `RW` | read / read-write |
| `RWXc` / `RWc` | copy-on-write variant (trailing `c`) |
| `NA` | `PAGE_NOACCESS` |
| `---` | no protection attribute (FREE/RESERVE rows only) |

`<type>`: `IMG` (mapped image), `PRV` (private), `MAP` (mapped data).
FREE/RESERVE regions are **not** dumped (no `.bin`), only recorded in the
manifest. `.pdata`/`.xdata` live inside the `IMG` region dumps.

## 6. `manifest.txt`

Header, then one line per region in ascending address order, then totals:

```
snapshot_full tag=dyndtor_000_rip1441a77c0 tid=95572
max_region_cap=none

0x0 size=0x10000 state=FREE prot=NA(0x1) type=MAP allocbase=0x0
0x7ffe76f67000 size=0x4000 state=RESERVE prot=---(0x0) type=IMG allocbase=0x7ffe76d00000
0x1000000 size=0x8000 state=COMMIT prot=R(0x2) type=MAP allocbase=0x1000000 -> dumped[region_1000000_8000_R_MAP.bin]

regions_seen=627 regions_dumped=461 regions_skipped_over_cap=0 bytes_dumped=0x24371000
```

Line grammar: `0x<base> size=0x<size> state=FREE|RESERVE|COMMIT
prot=<label>(0x<numeric>) type=IMG|PRV|MAP allocbase=0x<allocbase>
[-> dumped[<file>]]`. Only COMMIT rows carry `-> dumped[...]`.
`max_region_cap=none` — no cap, every committed region is dumped.

## 7. `snapshot.ext.json` — extended-state sidecar v2

Schema `slf.hvtrace.snapshot-ext.v2` (v1 = same shape without `fp_state`).
Top level: `schema`, `created_utc`, `freeze_rip`, `hit_tid`, then sections;
each section is either populated with per-field provenance or
`{"status": "absent", "note": ...}`.

Real excerpt:

```json
{
  "schema": "slf.hvtrace.snapshot-ext.v2",
  "freeze_rip": "0x1441a77c0", "hit_tid": 95572,
  "segment_bases": { "fs": "0x0", "fs_provenance": "same_hit_guest", "gs": "0x25a000", "gs_provenance": "same_hit_guest" },
  "control_state": { "cr0": "0x80050031", "cr2": "0x15efb8fdc", "cr3": "0x190f967000", "cr4": "0xb50ef8", "efer": "0x5d01",
                     "cr4_decode": {"la57":0,"pcide":0,"smap":1,"smep":1,"osxsave":1,"osfxsr":1,"fsgsbase":1},
                     "provenance": "same_hit_guest" },
  "system_configuration": { "dr6": "...", "dr7": "...", "star": "...", "lstar": "...", "cstar": "...",
                            "sfmask": "...", "kernel_gs_base": "...", "sysenter_cs": "...", "sysenter_esp": "...",
                            "sysenter_eip": "...", "cpl": 3, "gpat": "...", "dbgctl": "...", "provenance": "same_hit_guest" },
  "timing": { "tsc_guest_visible": "...", "tsc_aux": "...", "cr8": "...", "provenance": "same_hit_guest" },
  "fp_state": { "fctrl": {"value": "0x27f", "provenance": "parked_thread_context"}, ...,
                "st0".."st7", "mxcsr", "mxcsr_mask", "xmm0".."xmm15" (bare-hex values) },
  "cpuid": { "brand": "AMD Ryzen 9 5950X ...", "leaf1_eax/ecx/edx", "leaf7_ebx/ecx/edx", "leafD_eax", "xcr0": "0x7",
             "provenance": "host_cpu_enumeration" },
  "xstate": { "enabled_features": "0x7", "x87": true, "sse": true, "avx": true, "avx512": false,
              "full_image": "absent", "provenance": "host_cpu_enumeration" },
  "exception_handling": { "static_pdata": "present_in_module_regions", "veh_chain": "absent" }
}
```

Notes: `tsc_guest_visible` is the park TSC minus any cloaked cycles (what the
target's next RDTSC would return). `leaf7_ecx`/`leaf7_edx` are emitted by
builds since 2026-11-09 (older captures lack them — additive evolution).
`fp_state` values are byte-identical to the regs.txt rows.

## 8. `snapshot.ext3.json` — extended-state sidecar v3

Schema `slf.hvtrace.snapshot-ext.v3`. A **separate** file (v2 emission is
unchanged). Written last — its `integrity` section hashes every other file.
Skip with `--no-ext3`. Requires a v3 driver for `descriptor_tables`; every
other section is user-mode-only and always emitted. Values below are
**illustrative** (this section postdates the reference capture).

```json
{
  "schema": "slf.hvtrace.snapshot-ext.v3",
  "created_utc": "...", "freeze_rip": "0x...", "hit_tid": 1234,
  "cpu_identity": {
    "vendor": "AuthenticAMD", "vendor_hex": "41757468656e746943414d4400",
    "max_leaf": 16, "max_extended_leaf": 2147483656,
    "family": 25, "model": 33, "stepping": 0,
    "leaf1_eax": "0xa20f10",
    "provenance": "host_cpu_enumeration"
  },
  "tsc_calibration": {
    "leaf15_core_clock_numerator": 0, "leaf15_ref_clock_denominator": 0,
    "leaf16_base_mhz": 3400,
    "provenance": "host_cpu_enumeration"
  },
  "descriptor_tables": {
    "gdtr": { "base": "0xfffff80371fc9000", "limit": 87 },
    "idtr": { "base": "0xfffff80371fcb000", "limit": 4095 },
    "ldtr": { "selector": "0x0", "base": "0x0", "limit": 0, "attrib": "0x0" },
    "tr":   { "selector": "0x40", "base": "0xfffff80371fbd000", "limit": 103, "attrib": "0x8b" },
    "provenance": "same_hit_guest"
  },
  "fp_state_upper": {
    "ymm0_upper": { "value": "<32 hex chars>", "provenance": "parked_thread_context" },
    "...": "ymm0_upper..ymm15_upper (AVX); k0..k7 / zmm*_upper / zmm16..31 when XCR0 enables AVX-512; otherwise the section or those fields are absent",
    "encoding": "xsave_feature_bytes"
  },
  "integrity": {
    "algorithm": "sha256",
    "files": [ { "name": "manifest.txt", "bytes": 27440, "sha256": "..." }, ... ],
    "total_files": 480, "total_bytes": 609001472,
    "note": "hashes every regular file in this snapshot directory except snapshot.ext3.json itself (this file is written last)"
  }
}
```

- `cpu_identity.vendor` is the exact 12-byte CPUID leaf-0 string (NUL-padded,
  trimmed for the ASCII form; `vendor_hex` keeps the raw bytes) — the value
  the engine's vendor-law selection keys on. `family`/`model` are shown in
  SDM display form.
- `tsc_calibration`: leaf 0x15 numerator/denominator (core:ref clock ratio;
  `leaf15_nominal_tsc_hz` present only when the CPU enumerates it) and leaf
  0x16 base/max/bus MHz. Zeros ⇒ not enumerated; a section where the CPU
  enumerates neither leaf reads `status: "absent"`.
- `descriptor_tables` (needs the v3 driver tier): base/limit are what
  SGDT/SIDT store, selectors what SLDT/STR store, `attrib` the hidden
  descriptor-cache attribute word. Against a pre-v3 driver:
  `{"status": "absent", "note": "driver without descriptor-table capture ..."}`.
- `fp_state_upper` (user-mode, CONTEXT_XSTATE + `LocateXStateFeature`):
  YMM upper halves, and on AVX-512 hosts k-masks/ZMM sections — the XSAVE
  features beyond v2's `fp_state`. Absent (with reason) if AVX is not
  enabled in XCR0 or the read fails.
- `integrity`: sha256 + byte size of every file in the directory (sorted by
  name), self-excluded.

## 9. Consuming a capture — quick recipe

1. Read `hvtrace.json` for target/freeze identity.
2. `regs.txt` for machine state at the frozen instruction (check the
   `*_provenance` rows before trusting measured values).
3. `manifest.txt` to locate a region; the matching `region_*.bin` holds its
   bytes (`.pdata`/`.xdata` are inside `IMG` regions).
4. Sidecars for control/CPU facts: v2 for same-hit control state + fp +
   CPUID/xcr0, v3 for identity/TSC-calibration/descriptor tables/upper
   vector state + integrity verification.
5. Verify integrity by re-hashing files against `integrity.files` (v3).
