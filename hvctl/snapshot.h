/*!
    @file   snapshot.h

    @brief  Op1: cross-process memory snapshot in the exact Pinscan format.

    @details
    Reproduces the on-disk output of the Pin tool's ExecuteSnapshot /
    DumpFullAddressSpace (exec_tracker.cpp) but reading a *frozen* target process
    from the outside (VirtualQueryEx / ReadProcessMemory / GetThreadContext)
    instead of from inside via Pin. Call this while the target is suspended.

    Produces <outDir>\snapshot_full_<prefix>_000_rip<rip>\ containing:
      hvtrace.json, <tag>_regs.txt, <tag>_teb_*.bin, <tag>_peb_*.bin,
      <tag>_stack_*.bin, <tag>_tls_*.bin,
      region_<base>_<size>_<prot>_<type>.bin, manifest.txt
 */
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

//
// Descriptor-table registers MEASURED by the driver at the park event (v3
// QUERY tier; SVM's VMCB carries the full descriptor cache, hidden LDTR/TR
// fields included). `present` is false when the running driver predates the
// tier (QUERY returned fewer bytes) - the v3 sidecar then reports the section
// absent instead of guessing.
//
struct Ext3DescriptorTables
{
    bool present;
    unsigned long long gdtr_base, idtr_base, ldtr_base, tr_base;
    unsigned long gdtr_limit, idtr_limit, ldtr_limit, tr_limit;
    unsigned long ldtr_attrib, tr_attrib;
    unsigned short ldtr_selector, tr_selector;
};

//
// Write a full Pinscan-format snapshot of a frozen process.
//
//  hProc      - handle to the target (needs VM_READ | VM_OPERATION | QUERY_INFORMATION)
//  targetPid  - the target PID (used for provenance + module resolution in hvtrace.json)
//  hitTid     - the thread that hit the target RIP (its context is the register dump)
//  targetRip  - the RIP the freeze happened at (reported as snap_rip / rip)
//  outDir     - base output directory (the snapshot_full_* folder is created inside)
//  prefix     - tag prefix (Pinscan uses e.g. "manual"); becomes <prefix>_000_rip<rip>
//  measuredFsBase / measuredGsBase / haveMeasuredBases
//               - FS/GS bases MEASURED by the driver from the VMCB state-save
//                 area of the hitting thread at the park event. When
//                 haveMeasuredBases is false (pre-extension driver or missing
//                 hit), the snapshot falls back to the derived Win64 defaults
//                 and labels the provenance explicitly; an assumption is never
//                 silently written as a measured fact.
//
// Returns true if the snapshot directory and manifest were written.
//
bool WriteSnapshot(HANDLE hProc,
                   DWORD targetPid,
                   DWORD hitTid,
                   unsigned long long targetRip,
                   const std::string& outDir,
                   const std::string& prefix,
                   unsigned long long measuredFsBase = 0,
                   unsigned long long measuredGsBase = 0,
                   bool haveMeasuredBases = false,
                   unsigned long long measuredCr0 = 0,
                   unsigned long long measuredCr2 = 0,
                   unsigned long long measuredCr3 = 0,
                   unsigned long long measuredCr4 = 0,
                   unsigned long long measuredEfer = 0,
                   bool haveMeasuredControl = false,
                   unsigned long long measuredDr6 = 0,
                   unsigned long long measuredDr7 = 0,
                   unsigned long long measuredStar = 0,
                   unsigned long long measuredLStar = 0,
                   unsigned long long measuredCStar = 0,
                   unsigned long long measuredSfMask = 0,
                   unsigned long long measuredKernelGsBase = 0,
                   unsigned long long measuredSysenterCs = 0,
                   unsigned long long measuredSysenterEsp = 0,
                   unsigned long long measuredSysenterEip = 0,
                   unsigned long long measuredCpl = 0,
                   unsigned long long measuredGPat = 0,
                   unsigned long long measuredDbgCtl = 0,
                   unsigned long long measuredTscGuest = 0,
                   unsigned long long measuredTscAux = 0,
                   unsigned long long measuredCr8 = 0,
                   bool haveMeasuredExtended = false,
                   const Ext3DescriptorTables& descriptorTables = Ext3DescriptorTables(),
                   bool writeExt3 = true);
