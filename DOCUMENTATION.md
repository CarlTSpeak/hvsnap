# hvsnap

A Type-2 **AMD-V (SVM) hypervisor** that freezes a target process at an exact
instruction pointer — **invisibly and unremovably from the guest's point of
view** — and hands it off for analysis. Forked from
[tandasat/SimpleSvm](https://github.com/tandasat/SimpleSvm); the NPT
execute-trap machinery is adapted from
[tandasat/SimpleSvmHook](https://github.com/tandasat/SimpleSvmHook).

Two user-visible capabilities, both built on one primitive:

1. **Snapshot** — freeze at a RIP and dump the whole address space in the exact
   format the Pin tool (`MyPinTool`) produces, so it feeds the same downstream
   toolchain.
2. **Debugger hand-off** — freeze at a RIP so a normal user-mode debugger
   (x64dbg / WinDbg) can attach *at that instruction*, then resume — far cheaper
   than single-stepping a whole program into position.

---

## 1. Why a hypervisor (and why NPT)

The target class is protected / packed / self-checking code. That rules out the
obvious approaches:

| Technique | Problem |
|---|---|
| `INT3` (0xCC) patch | Modifies `.text` → self-checksums detect it; guest can rewrite the byte |
| Hardware `DR0` breakpoint | Visible to the guest via `GetThreadContext`; a debugger can clear `DR7` |
| Pin / DBI single-stepping | Enormous per-instruction overhead; detectable |

**NPT No-Execute** wins on every axis:

- The trap lives in the **nested page tables**, which the guest has **no
  instruction, register, or memory access to** — it cannot see, read, or clear
  it. *Much harder to detect and detach from inside the VM.*
- Only **execute** is trapped; **reads/writes pass through untouched**, so the
  target's own code-integrity checks read pristine bytes and pass.
- No target bytes are ever modified.

---

## 2. Architecture

```
 ┌─────────────────────────────┐        IOCTLs         ┌──────────────────────────┐
 │  hvctl.exe (user mode)       │ ───ARM/DISARM/QUERY──▶ │  hvsnap.sys (kernel)    │
 │  - resolves pid + RIP        │  \\.\hvsnap          │  - AMD-V hypervisor      │
 │  - allocs park stub in tgt   │                       │  - NPT NX execute-trap   │
 │  - suspends threads          │ ◀──Hit / HitTid ────  │  - parks hitting thread  │
 │  - snapshot / debug handoff  │                       │  on the park stub        │
 └─────────────────────────────┘                       └──────────────────────────┘
```

**Division of labour:** the driver does *only* the guest-invisible trigger and
the thread-park. **All memory reading is done from user mode** by `hvctl`
(`VirtualQueryEx` / `ReadProcessMemory` / `GetThreadContext`). This deletes the
riskiest kernel code (no in-kernel address-space walk, no disk I/O at high IRQL).

### The freeze primitive, step by step

1. `hvctl` resolves the target (`--pid`/`--name`, absolute `--rip` or
   `--module`+`--offset`), `VirtualAllocEx`'s a one-page **park stub**
   (`EB FE` = `jmp $`) in the target, and sends `ARM {pid, rip, parkStubVa}`.
2. The driver (at `PASSIVE_LEVEL`) attaches to the target
   (`KeStackAttachProcess`), reads its `CR3`, pins the target page
   (`MmProbeAndLockPages`), translates the RIP to a guest-physical address
   (`MmGetPhysicalAddress` — the identity-mapped NPT means GPA == SPA), **splits
   the covering 2 MB NPT PDE into 4 KB PTEs**, and sets **No-Execute** on the one
   target leaf. A cross-core nested-TLB flush follows.
3. When any thread of the target executes into that page, the CPU raises a
   **nested page fault (`#NPF`)**:
   - If `RIP == target && CR3 == target process` → **park**: the driver rewrites
     the guest RIP to the park stub (the thread now spins harmlessly in user
     mode) and latches `Hit`/`HitTid`.
   - Otherwise (a non-target instruction on the same page) → **step over**: make
     the leaf executable, single-step one instruction (`RFLAGS.TF`), then re-arm
     NX on the resulting `#DB`. Because NX is re-armed after *every* step, the
     target RIP always faults before it can execute (self-correcting).
4. `hvctl` polls `QUERY`, sees `Hit`, and `SuspendThread`s **every** thread in
   the target (a consistent, whole-process freeze).
5. Mode-specific work (snapshot / debugger hand-off), then restore: fix the
   parked thread's RIP back to the target, `DISARM` (driver restores the 2 MB
   page), resume threads, free the stub.

---

## 3. Building

### Driver (`hvsnap.sys`) — WDK for Visual Studio 2026 (VS 18)
Run from the `hvsnap` repo root:
```powershell
& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" `
  hvsnap.sln /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off
```
`/p:SignMode=Off` skips the WDK auto-test-sign step (which needs elevation); we
sign separately. Output: `x64\Release\hvsnap.sys` (beside `hvsnap.sln`, at the
repo root).

### Controller (`hvctl.exe`) — no admin needed to build
```powershell
hvctl\build-hvctl.cmd
```
(compiles `hvctl.cpp` + `snapshot.cpp` with the VS2026 x64 toolchain).

---

## 4. Host preparation (one-time)

The custom hypervisor runs on bare metal, so the Microsoft hypervisor must be
absent and test-signed kernel code must be allowed. See `tools\README.md` for
detail. Summary:

1. Disable **Memory Integrity / VBS / Hyper-V** (`bcdedit /set hypervisorlaunchtype off`)
   and **Secure Boot** (UEFI). Reboot. Confirm:
   ```powershell
   (Get-CimInstance Win32_ComputerSystem).HypervisorPresent   # must be False
   ```
2. `bcdedit /set testsigning on`, reboot (Test-Mode watermark is expected).

> Windows Update has re-enabled VBS on this box before — re-check after updates.

---

## 5. Sign, load, unload (elevated)

```powershell
cd tools   # from the hvsnap repo root
.\sign-hvsnap.ps1      # self-signed test cert -> trust -> signtool sign
.\load-hvsnap.ps1      # sc create type=kernel + start
# ... run hvctl ...
.\unload-hvsnap.ps1    # sc stop (devirtualizes all cores) + delete
```

**Stealth note — `HypervisorPresent` stays False while loaded (by design).** CPUID
is **passed through natively** — the driver does not intercept it at all. That
means both the *values* (hypervisor-present bit `CPUID.1:ECX[31]`, the
`0x40000000`/`0x40000001` vendor/interface leaves) **and the *timing*** are
identical to bare metal, so neither a CPUID feature check nor a `rdtsc;cpuid;rdtsc`
timing check can detect the hypervisor. (Internally, the control signals that used
to ride on CPUID — TLB flush, TSC-cloak toggling, unload — now use `VMMCALL`,
which is reflected as `#UD` for anything that isn't our own request, and the
load-time self-check uses a per-CPU flag.) A consequence is that
`Win32_ComputerSystem.HypervisorPresent` reads **False even when the driver is
loaded and virtualizing** — expected, not a failure. **To confirm the HV is
live**, use `Get-Service hvsnap` = `Running` plus a functional check
(`hvctl freeze`/`trace` succeeds).

Residual (not usermode-CPUID-reachable): the driver still intercepts MSR
(ring-0 only), VMRUN (privileged), VMMCALL (`#UD` to probes), and `#DB` (for the
single-step-over) — a target that single-steps *itself* and times `#DB` could in
principle notice added latency, but that is an exotic check.

> **Do not run with a kernel debugger (WinDbg/KD) attached** while the driver is
> loaded — the driver intercepts `#DB` (for the step-over), and KD's own use of
> debug exceptions is untested against it. DebugView is fine.

---

## 6. Using `hvctl`

```
hvctl <freeze|snapshot|debug> --pid <N> --rip <0xADDR> [options]
hvctl <freeze|snapshot|debug> --name <proc.exe> --module <mod.dll> --offset <0xN> [options]
```

| Option | Meaning |
|---|---|
| `--pid N` / `--name proc.exe` | target by PID or image name |
| `--rip 0xADDR` | absolute runtime address to freeze at |
| `--module mod.dll --offset 0xN` | resolve the RIP as module base + offset (ASLR-safe) |
| `--timeout N` | seconds to wait for the target to hit the RIP (default 60) |
| `--out DIR` | (snapshot) output base directory (default: cwd) |
| `--prefix NAME` | (snapshot) tag prefix (default `hv`) |
| `--hold N` | (freeze/debug) hold frozen N seconds instead of waiting for Enter |
| `--launch "exe"` | launch the exe **suspended**, arm, then resume — catches init code race-free |
| `--args "..."` | (launch) command-line arguments to forward to the launched exe |
| `--when EXPR` | conditional trigger: only freeze when `EXPR` holds at the RIP |
| `--when-size N` | operand width for `--when` (1/2/4/8, default 8) |
| `--skip N` | skip the first N matching hits before freezing |
| `--cloak` | hide the freeze gap from the target's RDTSC/RDTSCP (anti-timing) |
| `--keep-frozen` | (snapshot) stay frozen after the dump (thaw on Enter) instead of auto-resuming |
| `--terminate-after` | (snapshot) after the dump and a clean thaw, terminate the target process (`TerminateProcess`, waits up to 10 s and reports if the target did not exit) — for one-shot captures of dying / DRM-fragile processes |
| `--handoff` | (snapshot) after the dump, hand off to a debugger **at the RIP** (trap removed, RIP restored) |
| `--ring-mb N` / `--duration N` / `--max-records N` | (trace) capture-ring size, trace duration (s), record cap |

### Conditional triggers (`--when`)

Only freeze when a register condition holds at the RIP — essential for a hot
address (e.g. a VM dispatch handler hit millions of times). A non-match steps
over that invocation and keeps waiting.

```
--when rcx==0x5        freeze when RCX == 5
--when "r10&0xff!=0"   mask first: freeze when low byte of R10 is nonzero
--when rax>=0x1000 --skip 2   the 3rd time RAX >= 0x1000
```

Registers: `rax rcx rdx rbx rsp rbp rsi rdi r8..r15`. Ops: `== != < > <= >=`.
The hit line reports `matches=` so you can see how many times the condition held.

### TSC cloak (`--cloak`)

Structurally the freeze is invisible (NPT), but on thaw the target's wall-clock
has jumped by the snapshot/hold duration — a cross-freeze `RDTSC`/`RDTSCP` delta
check would see the gap. `--cloak` intercepts the target's
`RDTSC`/`RDTSCP` (CR3-gated) and subtracts the accumulated frozen cycles, so the
gap vanishes; other processes read the true TSC. Measured: a 3 s freeze's
cross-freeze delta dropped from ~10.5 G cycles to ~0.16 G (67×).

Caveats: while active, **all** guest `RDTSC` take a #VMEXIT (some system-wide
overhead) and the intercept persists until you run `hvctl cloak-off` or unload
the driver. A residual (~tens of ms) between commit and reschedule is not hidden.

```powershell
hvctl snapshot --pid 1234 --rip 0x... --cloak --out C:\dumps
hvctl cloak-off    # remove the intercept when finished
```

### Modes

- **`freeze`** — freeze at the RIP, wait (Enter or `--hold`), then thaw. Sanity
  check / manual inspection.
- **`snapshot`** — freeze, write a full Pinscan-format snapshot, then thaw.
  ```powershell
  hvctl snapshot --name target.exe --module target.exe --offset 0x14130 --out C:\dumps
  ```
  The dump is taken **while every thread is suspended**, so it is a coherent
  point-in-time image. By default the target auto-resumes the instant the dump
  finishes. To **stay frozen after the snapshot** (to take another snapshot,
  inspect it, or hand it off), keep it suspended with `--keep-frozen` (thaw on
  Enter) or `--hold N` (thaw after N seconds); the NPT trap stays armed and all
  threads stay suspended, so the held state is exactly the snapshotted state.
  ```powershell
  hvctl snapshot --pid 1234 --rip 0x... --out C:\dumps --keep-frozen
  hvctl snapshot --pid 1234 --rip 0x... --out C:\dumps --hold 10
  ```
  To **dump *and* hand off to a debugger** in one command, add `--handoff`: it
  writes the snapshot, then removes the NPT trap and restores the thread's RIP to
  the target (as `debug` mode does), leaving every thread suspended at the exact
  RIP for you to attach. This differs from `--keep-frozen` (which stays
  parked-on-stub with the trap still armed — good for a *second* snapshot, not a
  debugger).
  ```powershell
  hvctl snapshot --pid 1234 --rip 0x... --out C:\dumps --handoff
  # -> snapshot written, then attach x64dbg/WinDbg to PID 1234 at the RIP
  ```
- **`debug`** — freeze with the thread suspended **exactly at the RIP** and the
  NPT trap removed (bytes pristine), then wait while you attach a debugger:
  ```powershell
  hvctl debug --pid 1234 --rip 0x7ff600001130
  # -> attach x64dbg (File > Attach) or WinDbg (-p 1234); the target thread is
  #    suspended at 0x7ff600001130. Resume it in the debugger (Threads panel /
  #    Run), or press Enter in hvctl to let hvctl resume it.
  ```
- **`trace`** — log a register sample on **every** hit of the RIP **without
  freezing**, for watching loop evolution / VM & flattened-control-flow
  dispatchers. On each (optionally `--when`-gated) hit the driver captures a
  fixed record — 16 GPRs, RIP, RFLAGS, CR3, FS/GS base, segment selectors — into
  a lock-free ring, and continues. hvctl streams the ring to a `.bin`; convert
  offline with `trace-tocsv`.
  ```powershell
  hvctl trace --pid 1234 --rip 0x... --duration 10 --out trace.bin
  hvctl trace --launch "app.exe" --rip 0x... --when "rax==0x7" --out t.bin   # only when rax==7
  hvctl trace-tocsv trace.bin trace.csv
  ```
  Records: `hit_index,rax,rcx,…,r15,rip,rflags,cr3,fs_base,gs_base,cs,ss,ds,es,fs,gs`.
  Every hit is captured (never sampled); ring overrun is counted (`dropped`).
  **Cost:** each logged hit is two VM-exits (`#NPF` + the step-over `#DB`), and
  because the NX trap is per-**page**, *every* instruction on the target's 4 KB
  page is stepped — so a small function fully on the page costs ~10-20 step-overs
  per captured hit. The target throttles to the trap rate (order ~1M exits/s per
  core) while traced; it does not run at native speed. No FP/AVX in this phase.

### Launching the target (`--launch` / `--args`)

Instead of attaching to a running PID, `--launch` starts the exe **suspended**,
arms the trap before any code runs, then resumes — the only race-free way to
catch **init code** that executes at startup. Use `--rip` (absolute VA) here, not
`--module/--offset` (the loader hasn't populated the module list at
`CREATE_SUSPENDED`). Pass command-line arguments to the launched exe with
`--args` as a single quoted string (it becomes `argv[1..]`; the exe path is
`argv[0]`).

```powershell
hvctl freeze --launch "C:\Path\To\app.exe" --rip 0x140001130
hvctl snapshot --launch "C:\Path\To\app.exe" --args "--config dev.ini --verbose" --rip 0x140001130 --out C:\dumps
```

The RIP's page must be mapped at suspend (true for image sections; a region a
packer/JIT allocates later will fail to arm — `err 998`).

### Diagnostic helper: `probe.exe`

`hvctl\build-probe.cmd` builds a tiny standalone tool (no driver needed) that
launches an exe and polls a chosen VA, reporting when it first becomes mapped
and what protection it has:

```
probe.exe "C:\Path\To\app.exe" 0x140012000 [poll-window-ms]
```

Use it to pick a workable freeze RIP when the obvious entry is on a page a
packer/JIT maps late (the `err 998` case above), and to observe when an SMC
region appears.

---

## 7. Snapshot output (Op1)

`snapshot` reproduces the Pin tool's `ExecuteSnapshot`/`DumpFullAddressSpace`
output **byte-for-byte**, so it drops into the existing toolchain. In
`<out>\snapshot_full_<prefix>_000_rip<rip>\`:

| File | Contents |
|---|---|
| `hvtrace.json` | provenance the Pin dumps don't carry: `hvtrace_version`, `created_utc` (ISO-8601), `target` {`pid`, `image` full path, `hit_tid`}, `freeze` {`rip`, `module`, `module_base`, `module_size`, `module_offset` — resolved from the target's own module list, not the CLI hint}, `snapshot` {`prefix`, `tag`, `format`} |
| `snapshot.ext.json` | versioned extended-state sidecar (schema `slf.hvtrace.snapshot-ext.v2`) — see §7.5 |
| `<tag>_regs.txt` | `# pinscan snapshot register state` + `key=0xhex` lines: `snap_rip`, `tid`, GPRs, `rip`, `rflags`, `seg_cs..seg_gs`, `fs_base`, `gs_base`, `mxcsr`, `xmm0..15` (32 hex chars each), `dr0..dr3` (parked-thread CONTEXT), `fctrl..st7` |
| `<tag>_teb_<addr>_2000.bin` / `<tag>_peb_<addr>_1000.bin` | TEB (0x2000) / PEB (0x1000) |
| `<tag>_stack_<addr>_<size>.bin` | full stack (TEB `StackLimit`→`StackBase`) |
| `<tag>_tls_ptrarray/_block/_slots_*.bin` | TLS pointer array, per-module blocks, static slots |
| `region_<base>_<size>_<prot>_<type>.bin` | one raw dump per committed region |
| `manifest.txt` | every region: `0x<base> size=… state=COMMIT/RESERVE/FREE prot=<label>(0x…) type=IMG/PRV/MAP allocbase=… -> dumped[…]` + totals. `<label>` decodes the base protection: `X, RX, RWX, RWXc, R, RW, RWc, NA` (trailing `c` = copy-on-write, e.g. packed image sections; `NA` = NOACCESS; `---` = no protection, i.e. FREE/RESERVE) |

`rip`/`snap_rip` are the freeze point; guard/`NOACCESS` pages are temporarily
unlocked (`VirtualProtectEx`) then restored. Text files use LF line endings.

### 7.5 Extended-state sidecar (`snapshot.ext.json`)

A versioned JSON sidecar emitted beside the Pinscan dump; schema
`slf.hvtrace.snapshot-ext.v2` (v1 = the same shape without `fp_state`). Its
purpose is to make hypervisor-measured and host-enumerated facts available as
*typed, provenance-labeled* data rather than prose. Every component carries its
own provenance; anything the running driver/hvctl pair cannot measure is
reported as `{"status": "absent", "note": …}` — **absent is never zero-filled
or guessed**.

| Section | Fields | Provenance |
|---|---|---|
| `segment_bases` | `fs`, `gs` (the real per-thread bases at the freeze) | `same_hit_guest` |
| `control_state` | `cr0`, `cr2`, `cr3`, `cr4`, `efer` + `cr4_decode` (`la57`, `pcide`, `smap`, `smep`, `osxsave`, `osfxsr`, `fsgsbase`) | `same_hit_guest` |
| `system_configuration` | `dr6`, `dr7`, `star`, `lstar`, `cstar`, `sfmask`, `kernel_gs_base`, `sysenter_cs/esp/eip`, `cpl`, `gpat`, `dbgctl` | `same_hit_guest` |
| `timing` | `tsc_guest_visible` (park TSC minus cloaked cycles), `tsc_aux` (MSR C0000103 from the exit context), `cr8` | `same_hit_guest` |
| `fp_state` | `fctrl..st7`, `mxcsr`, `mxcsr_mask`, `xmm0..15`, each `{value, provenance}` — Windows CONTEXT/XSAVE encoding, byte-identical to the `regs.txt` rows | `parked_thread_context` |
| `cpuid` | `brand`, `leaf1_eax/ecx/edx`, `leaf7_ebx/ecx/edx`, `leafD_eax`, `xcr0` | `host_cpu_enumeration` (same logical processors the guest runs on) |
| `xstate` | decode of `xcr0` (`x87`/`sse`/`avx`/`avx512` enabled booleans); `full_image: "absent"` — YMM/ZMM upper halves and k-masks are explicitly deferred (the `xcr0` row already gates consumers) | `host_cpu_enumeration` |
| `exception_handling` | `static_pdata: "present_in_module_regions"` (.pdata/.xdata live inside the dumped image bytes); dynamic VEH walk documented as deferred, not guessed | n/a (pointer) |

**Same-hit semantics:** `same_hit_guest` values are captured in the VM-exit of
the freeze itself — they are the values the target would have observed at the
exact instruction, not reconstructed ones. `parked_thread_context` values are
read from the suspended thread's CONTEXT after the freeze (consistent because
every thread is suspended). `host_cpu_enumeration` facts (CPUID) describe the
host CPU, not the frozen instruction, and are labeled as such.

**Compatibility note:** file and schema names keep the `hvtrace` prefix for
compatibility; a format rename would be a separate, versioned change. The
engine reads exactly `hvtrace.json` and the `slf.hvtrace.snapshot-ext.*`
schema ID, and every existing capture depends on them — the *tool* was renamed
to hvsnap, the *format* was not.

---

## 8. Design notes & limitations

- **Undetectable / unremovable:** the trap is nested-paging state — no guest
  register or byte reveals it, and the guest cannot alter the nested tables.
  Only *reads* pass through, so code checksums pass.
- **Step-over is page-granular.** While the target executes on the trapped 4 KB
  page (before reaching the RIP), every instruction on that page takes a
  `#NPF`+`#DB` round trip, so the target runs slowly *during that window only*.
  Cheap for a specific RIP; heavy only if the RIP shares its page with a hot
  loop. Correctness is unaffected.
- **Shared pages:** if the RIP is in a *shared, unmodified* page (e.g. a clean
  system DLL mapped at the same physical page across processes), NX applies to
  that physical page system-wide; other processes touching it get stepped over
  (CR3-gated, so only the target ever parks). Private/packed/self-modified code
  (the usual target) is unaffected.
- **Minor timing leak:** during the one-instruction step-over the guest's
  `RFLAGS.TF` is briefly set; a `PUSHF` executed in that single instruction could
  observe it. Transient; accepted.
- **Consistency:** `hvctl` suspends *all* target threads before dumping/handing
  off, so the snapshot is coherent and sibling threads can't race.
- **Kernel debugger:** don't attach KD while loaded (see §5).

---

## 9. Validation status (hardware-tested on AMD Ryzen 9 5950X)

All exercised live with the driver signed + loaded, VBS off, test-signing on:

- **Load/unload:** loads, virtualizes all 32 logical CPUs, devirtualizes cleanly;
  multiple back-to-back cycles, no BSOD.
- **Freeze:** target frozen at the exact RIP — progress provably halts for the
  full hold, then resumes; target survives.
- **Snapshot:** produced `regs.txt` (with e.g. `rcx` = the actual call argument
  at the RIP), `manifest.txt`, 53 region dumps + all OS-structure files; the
  region containing the target held the real, correct instruction bytes.
- **Extended sidecar:** every `fp_state` field verified byte-identical to the
  corresponding `regs.txt` rows (33/33 fields) on live captures; the CPUID
  leaf-7 extension (`leaf7_ecx`/`leaf7_edx`) verified against a capture taken
  with the rebuilt binary; v1 and v2 sidecar samples kept byte-stable across
  loader tests.
- **Trace mode:** per-hit register records with every hit captured (ring
  overrun counted, never silently sampled); used for dispatcher/loop
  observation on protected targets.
- **Debug hand-off:** hit thread left suspended exactly at the RIP with the NPT
  trap removed; frozen for the whole hold; resumes cleanly.

> The hvsnap rename (from `hvtrace`) is build-verified (hvctl + probe + driver,
> Release x64; hvctl has 3 known C4100 warnings, driver clean — see the Build
> section in README.md) but has **not** been loaded or run on hardware; the
> pre-rename build is the one the validation above was performed on.

### Test fixture
`hvtarget.c` (in the session scratchpad): prints its PID and the address of a
`target_func` it calls in a loop; used as `hvctl <mode> --pid <PID> --rip <addr>`.

---

## 10. Source map

```
hvsnap\
  README.md               top-level overview + provenance/license
  DOCUMENTATION.md        this file
  hvsnap.sln
  hvsnap\                 driver (AMD-V/SVM)
    hvsnap.cpp            SVM setup, #VMEXIT dispatch, NPT split/arm/disarm,
                            #NPF + #DB handlers, IOCTL device, measured-state capture
    hvsnap.hpp            VMCB / SVM structures
    hvsnap_ioctl.h        shared IOCTL contract (driver + hvctl)
    x64.asm               SvLaunchVm / SvHandleVmExit linkage
    hvsnap.vcxproj / hvsnap.ruleset
  hvctl\                   user-mode controller (vendor-neutral)
    hvctl.cpp              CLI, arm/poll/suspend/thaw, freeze/snapshot/debug/trace modes
    snapshot.cpp/.h        Pinscan-format snapshot + snapshot.ext.json sidecar
    probe.cpp              standalone mapped/executable diagnostic (§6)
    build-hvctl.cmd        build script (VS2026 x64)
    build-probe.cmd
  tools\                   sign-hvsnap.ps1 / load-hvsnap.ps1 / unload-hvsnap.ps1 / README.md
  upstream\SimpleSvm\, upstream\SimpleSvmHook\   pristine upstream references (not built)
```
