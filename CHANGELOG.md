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
