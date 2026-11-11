/*!
    @file   hvsnap_ioctl.h

    @brief  Shared IOCTL contract between the hvsnap kernel driver and the
            privileged user-mode controller (hvctl.exe).

    @details
    The controller does ALL target identification in user mode:
      - image name  -> PID            (Toolhelp32 snapshot)
      - module+off  -> absolute RIP   (module list)
      - writes 0xCC (INT3) at the absolute RIP (saving the original byte)
      - VirtualAllocEx a 1-page "park stub" (EB FE = jmp $) in the target
    then ARMs the driver with {pid, rip, parkStubVa}.

    The driver's only job: when a thread of <pid> executes the INT3 at <rip>,
    transparently intercept the #BP (before the guest IDT), redirect that
    thread's RIP to the park stub so it spins harmlessly in user mode, and flag
    the hit. The controller polls QUERY, then suspends every thread in the target
    (consistent freeze) and does its work (snapshot or debugger hand-off), then
    restores the original byte, SetThreadContext(RIP=rip) on the parked
    thread(s), DISARMs, and resumes.

    This header is plain C so it compiles in both the WDM driver and a Win32 app.
 */
#pragma once

#define HVSNAP_DEVICE_NAME     L"\\Device\\hvsnap"
#define HVSNAP_SYMLINK_NAME    L"\\DosDevices\\hvsnap"
#define HVSNAP_WIN32_NAME      L"\\\\.\\hvsnap"

//
// 0x800-0xFFF is the customer-defined IOCTL function range.
//
#define HVSNAP_IOCTL_ARM        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HVSNAP_IOCTL_DISARM     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define HVSNAP_IOCTL_QUERY      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Turn off TSC cloaking (removes the RDTSC/RDTSCP intercept + stolen-cycle
// correction). Cloak otherwise persists until the driver unloads.
#define HVSNAP_IOCTL_CLOAK_OFF  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Register-trace drain: copy newly captured records into the caller's output
// buffer (see HVSNAP_DRAIN_HEADER). Repeatable; poll it in a tight loop.
#define HVSNAP_IOCTL_TRACE_DRAIN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Stop tracing and free the ring (call after DISARM + a final drain).
#define HVSNAP_IOCTL_TRACE_STOP  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// One captured register sample (feature: register trace). Fixed 192-byte layout,
// packed, little-endian. HitIndex is the 0-based capture sequence AND the record
// validity marker (written last by the producer). Cheap classes only (all live
// in the VMCB save area / pushed GPRs); no FP/AVX in this phase.
//
#pragma pack(push, 1)
typedef struct _HVSNAP_RECORD
{
    unsigned __int64 HitIndex;
    unsigned __int64 Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    unsigned __int64 R8, R9, R10, R11, R12, R13, R14, R15;
    unsigned __int64 Rip;
    unsigned __int64 Rflags;
    unsigned __int64 Cr3;
    unsigned __int64 FsBase;
    unsigned __int64 GsBase;
    unsigned __int16 Cs, Ss, Ds, Es, Fs, Gs;    // segment selectors
    unsigned __int32 Pad;
} HVSNAP_RECORD, *PHVSNAP_RECORD;
#pragma pack(pop)

//
// Header the driver writes at the front of a TRACE_DRAIN output buffer, followed
// by RecordCount HVSNAP_RECORDs. Caller supplies a large output buffer.
//
typedef struct _HVSNAP_DRAIN_HEADER
{
    unsigned __int32 RecordSize;    // sizeof(HVSNAP_RECORD)
    unsigned __int32 RecordCount;   // records that follow in THIS drain
    unsigned __int64 TotalWritten;  // producer's total captured-so-far
    unsigned __int64 TotalDropped;  // cumulative records lost to ring overrun
    unsigned __int64 MoreAvailable; // nonzero if more records are ready right now
} HVSNAP_DRAIN_HEADER, *PHVSNAP_DRAIN_HEADER;

//
// Conditional trigger (predicate). Evaluated in the #NPF handler each time the
// target RIP is reached in the target process. When it does NOT match, the
// driver single-steps over the instruction and keeps waiting (the same
// step-over path used for sibling instructions) instead of parking - so a hot
// address (e.g. a VM dispatch handler) only freezes on the invocation you want.
//
#define HVSNAP_PRED_NONE   0u  // always fire on the first hit (legacy behavior)
#define HVSNAP_PRED_REG    1u  // compare a general-purpose register

// Comparison operators (unsigned).
#define HVSNAP_OP_EQ       0u  // (val & Mask) == Imm
#define HVSNAP_OP_NE       1u  // (val & Mask) != Imm
#define HVSNAP_OP_ULT      2u  // (val & Mask) <  Imm
#define HVSNAP_OP_UGT      3u  // (val & Mask) >  Imm
#define HVSNAP_OP_ULE      4u  // (val & Mask) <= Imm
#define HVSNAP_OP_UGE      5u  // (val & Mask) >= Imm

// GP register selector uses x86 encoding order:
//   0 rax  1 rcx  2 rdx  3 rbx  4 rsp  5 rbp  6 rsi  7 rdi  8..15 r8..r15
typedef struct _HVSNAP_PREDICATE
{
    unsigned __int32 Kind;          // HVSNAP_PRED_*
    unsigned __int32 Reg;           // GP register index 0..15 (for HVSNAP_PRED_REG)
    unsigned __int32 Op;            // HVSNAP_OP_*
    unsigned __int32 Size;          // operand width in bytes: 1/2/4/8 (val & Imm truncated to it)
    unsigned __int64 Imm;           // comparison immediate
    unsigned __int64 Mask;          // AND-mask applied to the register (0 => all-ones)
} HVSNAP_PREDICATE, *PHVSNAP_PREDICATE;

//
// Input for HVSNAP_IOCTL_ARM.
//
typedef struct _HVSNAP_ARM_REQUEST
{
    unsigned __int64 TargetPid;     // process id to watch
    unsigned __int64 TargetRip;     // absolute VA to trap on (guest virtual)
    unsigned __int64 ParkStubVa;    // VA of an "EB FE" (jmp $) stub in the target address space
    HVSNAP_PREDICATE Predicate;    // conditional trigger; Kind=NONE => fire on first hit
    unsigned __int64 HitSkip;       // skip this many predicate-matching hits before parking (0 => first)
    unsigned __int32 CloakTsc;      // non-zero => hide the freeze gap from the target's RDTSC/RDTSCP
    unsigned __int32 TraceEnabled;  // non-zero => register-trace mode: on each (predicate-matching)
                                    //            hit, capture a record and CONTINUE (never park)
    unsigned __int64 TraceRingBytes;// (trace) size of the driver's capture ring buffer in bytes
} HVSNAP_ARM_REQUEST, *PHVSNAP_ARM_REQUEST;

//
// Output for HVSNAP_IOCTL_QUERY.
//
// Legacy size (through StolenTsc) is HVSNAP_STATE_V1_SIZE: older controllers
// may pass a buffer of that size; the driver fills the core fields then and
// the measured segment bases only when the full struct fits.
//
#define HVSNAP_STATE_V1_SIZE   48u
typedef struct _HVSNAP_STATE
{
    unsigned __int32 Active;        // non-zero while an ARM session is in effect
    unsigned __int32 Hit;           // non-zero once a target thread has hit and parked
    unsigned __int64 HitTid;        // thread id of the first thread that hit (0 if none yet)
    unsigned __int64 TargetRip;     // echo of the armed RIP
    unsigned __int64 ParkedCount;   // number of target threads redirected to the park stub
    unsigned __int64 MatchCount;    // times the predicate has matched at the target RIP
    unsigned __int32 CloakActive;   // non-zero while TSC cloaking is intercepting the target
    unsigned __int32 Reserved1;
    unsigned __int64 StolenTsc;     // accumulated cycles hidden from the target's TSC
    unsigned __int64 HitFsBase;     // MEASURED FS base (VMCB state-save) of the
                                    // first thread AT the target RIP; 0 also when
                                    // no hit yet - check Hit first
    unsigned __int64 HitGsBase;     // MEASURED GS base (VMCB state-save), same event
    unsigned __int64 HitCr0;        // MEASURED CR0 at the same park event
    unsigned __int64 HitCr2;        // MEASURED CR2 (page-fault linear address)
    unsigned __int64 HitCr3;        // MEASURED CR3 (directory base, target)
    unsigned __int64 HitCr4;        // MEASURED CR4 (LA57/PCID/SMAP... flags)
    unsigned __int64 HitEfer;       // MEASURED EFER MSR (LMA/NXE/SCE...)
    unsigned __int64 HitDr6;        // MEASURED guest DR6 (VMCB), same event
    unsigned __int64 HitDr7;        // MEASURED guest DR7 (VMCB), same event
    unsigned __int64 HitStar;       // MEASURED STAR (VMCB)
    unsigned __int64 HitLStar;      // MEASURED LSTAR (VMCB)
    unsigned __int64 HitCStar;      // MEASURED CSTAR (VMCB)
    unsigned __int64 HitSfMask;     // MEASURED SFMASK (VMCB)
    unsigned __int64 HitKernelGsBase; // MEASURED KERNEL_GS_BASE (VMCB)
    unsigned __int64 HitSysenterCs; // MEASURED SYSENTER_CS (VMCB)
    unsigned __int64 HitSysenterEsp;// MEASURED SYSENTER_ESP (VMCB)
    unsigned __int64 HitSysenterEip;// MEASURED SYSENTER_EIP (VMCB)
    unsigned __int64 HitCpl;        // MEASURED CPL at park (VMCB)
    unsigned __int64 HitGPat;       // MEASURED guest PAT (VMCB)
    unsigned __int64 HitDbgCtl;     // MEASURED DEBUG_CTL MSR (VMCB)
    unsigned __int64 HitTscGuest;   // GUEST-VISIBLE TSC at park (park host TSC
                                    // minus cloaked cycles), same event
    unsigned __int64 HitTscAux;     // MEASURED TSC_AUX (MSR 0xC0000103) read in
                                    // the exit context (guest value resident)
    unsigned __int64 HitCr8;        // MEASURED guest CR8 (TPR) latched at exit
                                    // entry BEFORE the host IRQL raise
} HVSNAP_STATE, *PHVSNAP_STATE;
