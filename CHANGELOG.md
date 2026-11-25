# Changelog

## 2026-11-25 — Stage A VA-traps (branch z/va-traps-20261125)

**Defect (owner: "basic unpacking")**: an NPT execute-trap armed at launch on
a page the loader later rewrites never fires. `SvArmNptTrap` resolved the
target VA once (MmGetPhysicalAddress), pinned that frame with an MDL and
NXed its 4 KB leaf — after the loader's in-place decryption copy-on-writes
the RWX image page, the VA executes a NEW private frame while the trap
watches the OLD pinned one. Seen at 0x142b16d78 (vmp_init_decrypt_vm_entry)
and 0x142b6ceaa (_isindst_nolock); untouched RWX regions trap fine.

**Fix (Stage A)**: new `HVSNAP_IOCTL_RECHECK` — re-resolve the trapped VA
and MOVE the trap when its backing frame changed. The move never repoints a
live leaf's PFN (that would alias old-GPA accesses onto the new frame):
(1) restore the old 2 MB PDE + nested-TLB flush, free the old split table,
unlock the old MDL (NptArmed stays 1 so an in-flight #NPF handler always
sees a valid g_Target); (2) pin the new frame and install a fresh split
table + NX leaf for the NEW GPA — its own 2 MB region, its own saved PDE;
(3) flush. Mid-move failure finishes a full disarm (no half-armed state).
Serialized by `g_RecheckBusy`; no-op success when unchanged/not armed/
already parked. `hvctl` polls RECHECK in the wait-for-hit loop
(`--recheck-ms=N`, default 250, 0 = off), prints every move, and does one
final re-resolve before reporting no-hit (with a 1 s grace wait after a
final move).

**Compatibility**: ARM/DISARM/QUERY unchanged; RECHECK is additive; old
hvctl against new driver simply never rechecks (same behavior as before
the fix). No record-format or output change.

**Not yet done**: Stage B (guest page-table watch: write-trap the PTE
chain so the move is event-driven instead of polled) and the on-machine
regression (load window required; regression cases 0x142b16d78 and
0x142b6ceaa must fire from --launch, untouched-page traps unchanged).

**Re-split fix (pre-review, same branch)**: `SvFillSplitTableFromPde` — the
identity-fill now handles BOTH PDE shapes: a 2MB large page (base = PFN<<9)
and an ALREADY-SPLIT table pointer (the existing 512 leaves are copied via
MmGetVirtualForPhysical, so a second COW move re-splits the same region
without building leaves from a table pointer misread as a frame). Used by
both ARM and RECHECK. Gap found by self-review during F's independent
kernel-safety review; flagged to F before the review landed.

**Review fixes (F's kernel-safety review of b738052 + 8403e90)**:
(1) BLOCKING — RECHECK now tracks a `newLocked` flag: an MDL whose
`MmProbeAndLockPages` raised is freed without unlocking (no bugcheck /
refcount corruption when the target exits or unmaps between polls), and
the error propagates instead of returning SUCCESS. (2) The new split
table is allocated AND filled BEFORE any teardown, so `SplitTable` is
never null while `NptArmed` is 1; the #DB handler null+arm checks before
touching the table. (3) The >1 TB check and the table allocation moved
before the swap — every failure path now leaves the old trap fully armed.
(4) gpa comes from the locked MDL's PFN (`MmGetMdlPfnArray[0]`), not a
second lookup — in both RECHECK and ARM. (5) PDE writes build the entry
in a local and publish with ONE 64-bit store — no concurrent walk can
observe a not-present or frame-0 PDE — in RECHECK and ARM. (8) hvctl
surfaces RECHECK DeviceIoControl failures instead of silently reporting
'no hit'. Non-blocking (6)/(7) accepted as-is per the review.

**Review-2 fixes** (second kernel-safety review):
(1) BLOCKING — `SvFillSplitTableFromPde` now fills ONLY from a 2MB
large-page PDE and refuses anything else (the already-split copy path
misread a table pointer through the 2MB view — wrong frame, unchecked
copy, and it would have carried the OLD NX leaf into the new table,
bugchecking the #NPF handler). A same-region RECHECK move fills from
`g_Target.SavedPde` (the original large page) instead; the copy and
`MmGetVirtualForPhysical` are gone.
(2) BLOCKING — the swap retires the OLD leaf FIRST (restore original PDE
+ flush) and only then publishes the new state and repoints, so an
old-frame fetch on another core always matches the still-live
`TargetGpa` (no :1095 bugcheck window, no half-published handler state).
(3) The #DB handler clears our TF on the bail-out path too and reads
the table through one local.
(4) All three PDE publications are `InterlockedExchange64` stores (the
single 64-bit write is guaranteed by the language, not just by intent).
(5) hvctl stops RECHECK polling after the first failure (a target that
exits would otherwise print the error every 250 ms).
