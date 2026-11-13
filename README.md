# hvsnap

Guest-invisible, point-in-time capture of protected / packed / self-checking
Windows x64 targets, built on an **AMD-V (SVM) hypervisor** whose trap lives in
the **nested page tables (NPT)**: no target byte is modified, no guest-visible
register reveals it, and code-integrity checksums read pristine bytes. A
user-mode controller (`hvctl`) drives it.

*(Renamed from `hvtrace`, 2026-11-11 — tool, binary, driver, service and device
names. File and schema names keep the `hvtrace` prefix for compatibility; a
format rename would be a separate, versioned change: snapshots still write
provenance to `hvtrace.json` and the sidecar schema ID
`slf.hvtrace.snapshot-ext.v2`, because the engine and every existing capture
read exactly those.)*

## Capabilities

- **Freeze at an exact RIP** — NPT no-execute on the covering 4 KB leaf;
  non-target instructions on the page are stepped over (self-correcting), so
  the target always parks *at* the requested instruction.
- **Full snapshot** (`hvctl snapshot`) — the whole address space in
  Pinscan-compatible format (`regs.txt`, TEB/PEB, full stack, TLS blocks,
  per-region dumps, `manifest.txt` page walk), taken with **every thread
  suspended** — a coherent point-in-time image.
- **Extended-state sidecar** (`snapshot.ext.json`, schema
  `slf.hvsnap.snapshot-ext.v2`) — same-hit guest state (FS/GS bases, CR0/2/3/4,
  EFER, DR6/7, SYSCALL/SYSENTER MSRs, CPL, PAT, DBGCTL, guest-visible TSC,
  TSC_AUX, CR8), full parked x87/SSE state, and CPUID/xcr0 host facts — every
  field provenance-labeled; absent is reported, never zero-filled.
- **v3 sidecar** (`snapshot.ext3.json`, schema
  `slf.hvtrace.snapshot-ext.v3`; **see `V3.md`**) — measured CPU identity
  (leaf-0 vendor string), TSC calibration leaves, descriptor tables
  (GDTR/IDTR/LDTR/TR at the park event — SGDT/SIDT/SLDT/STR ground truth),
  XSAVE upper state (YMM halves, k-masks, ZMM), and a sha256 integrity list
  of every emitted file. v2 emission is untouched; `--no-ext3` skips it.
  Build-validated, hardware validation pending.
- **Debugger hand-off** (`debug` / `--handoff`) — leaves the thread suspended
  exactly at the RIP with the trap removed, for x64dbg/WinDbg attach.
- **Register trace** (`trace`) — per-hit GPR/RIP/RFLAGS/CR3/segment records on
  every hit of a RIP (loop/dispatcher observation), ring-buffered with honest
  overrun counting.
- **Conditional freeze** (`--when rcx==0x5`, `--skip N`) — arm on hot addresses.
- **TSC cloak** (`--cloak`) — subtracts the frozen interval from the target's
  RDTSC/RDTSCP so cross-freeze timing checks see no gap (~67× reduction
  measured).
- **One-shot flows** — `--launch`/`--args` (catch init code race-free),
  `--keep-frozen`, `--hold`, `--terminate-after` (clean thaw then terminate).
- **`probe.exe`** — standalone "when does this VA become mapped/executable"
  diagnostic for picking workable freeze RIPs.

## Status

Hardware-validated on AMD (Ryzen 9 5950X): load/unload cycles, freeze, full
snapshot + sidecar (sidecar `fp_state` verified byte-identical to `regs.txt`),
trace, debug hand-off, TSC cloak. See `DOCUMENTATION.md` §9.
**The renamed tree builds clean** (hvctl, probe, driver — Release x64, see
Build below); it has **not** been loaded or run on hardware — the §9
validation was performed with the pre-rename `hvtrace` build. The v3 work
(sidecar + descriptor-table driver tier, now on main) is likewise
build-validated only (hvctl: same 3 known C4100s, driver: zero warnings;
SHA-256 implementation validated 11/11 against hashlib vectors) — the
descriptor-table/XSTATE paths need a quiet window with the v3 driver loaded,
coordinated with the team. **`V3.md`** documents the new features and the
executables.

**Intel hosts:** not supported today — the driver is SVM/AMD-V only. An Intel
VT-x + EPT variant is a recorded future item.

## Build (verified on the renamed tree, 2026-11-11)

Toolchain: VS2026 (18.10.3) + WDK `WindowsKernelModeDriver10.0`. From the repo
root:

```
hvctl\build-hvctl.cmd     # hvctl.exe  (cl /EHsc, x64)
hvctl\build-probe.cmd     # probe.exe  (cl /EHsc, x64)
"C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" ^
  hvsnap.sln /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off
```

- `hvctl.exe` — **3 warnings** `C4100` (parameters `hProc`, `pid`, `tag` of
  `WriteExtendedSidecar`, `hvctl/snapshot.cpp:400-402`, are no longer used by
  its body — vestigial; harmless).
- `probe.exe` — clean, no warnings.
- `hvsnap.sys` — clean, no warnings; output `x64\Release\hvsnap.sys`;
  `Inf2Cat`/`DrvCat` skipped (no inf/catalog by design). Driver **not loaded**
  (loading requires elevation + test-signing; see `tools/README.md`).

## Feeding the snapshots into Semantic Lifting Framwork

Snapshots are consumed by the product as `--input-kind=hvtrace-snapshot` and
read from `hvtrace.json` / `snapshot.ext.json` (`slf.hvtrace.snapshot-ext.*`).
None of those format names changed with the tool rename — captures from
hvsnap and from the pre-rename hvtrace builds are interchangeable.

## Building & running

Requires WDK for VS2026, admin for sign/load, VBS/Hyper-V off, test-signing on.
Quick start: `DOCUMENTATION.md` §3–§7 (full manual: architecture, build, host
prep, every `hvctl` option, output formats, design notes). Host prep and
sign/load/unload scripts: `tools/README.md`.

## Provenance & license

MIT — see `LICENSE` (Copyright (c) 2026 SLF Labs).

Fork of [tandasat/SimpleSvm](https://github.com/tandasat/SimpleSvm) (MIT), with
the NPT execute-trap machinery adapted from
[tandasat/SimpleSvmHook](https://github.com/tandasat/SimpleSvmHook) (MIT) —
verbatim MIT notices in `THIRD_PARTY/`, derivation record in `LINEAGE.md`;
they apply to the derived portions (see `LINEAGE.md` for the file map).
