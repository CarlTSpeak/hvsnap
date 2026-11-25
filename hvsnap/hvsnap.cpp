/*!
    @file       hvsnap.cpp

    @brief      All C code.

    @author     Satoshi Tanda

    @copyright  Copyright (c) 2017-2020, Satoshi Tanda. All rights reserved.
 */
#define POOL_NX_OPTIN   1
#include "hvsnap.hpp"

#include <intrin.h>
#include <ntifs.h>
#include <stdarg.h>
#include "hvsnap_ioctl.h"

EXTERN_C DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD SvDriverUnload;
static CALLBACK_FUNCTION SvPowerCallbackRoutine;

EXTERN_C
VOID
_sgdt (
    _Out_ PVOID Descriptor
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
DECLSPEC_NORETURN
EXTERN_C
VOID
NTAPI
SvLaunchVm (
    _In_ PVOID HostRsp
    );

//
// x86-64 defined structures.
//

//
// See "2-Mbyte PML4E-Long Mode" and "2-Mbyte PDPE-Long Mode".
//
typedef struct _PML4_ENTRY_2MB
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT64 Valid : 1;               // [0]
            UINT64 Write : 1;               // [1]
            UINT64 User : 1;                // [2]
            UINT64 WriteThrough : 1;        // [3]
            UINT64 CacheDisable : 1;        // [4]
            UINT64 Accessed : 1;            // [5]
            UINT64 Reserved1 : 3;           // [6:8]
            UINT64 Avl : 3;                 // [9:11]
            UINT64 PageFrameNumber : 40;    // [12:51]
            UINT64 Reserved2 : 11;          // [52:62]
            UINT64 NoExecute : 1;           // [63]
        } Fields;
    };
} PML4_ENTRY_2MB, *PPML4_ENTRY_2MB,
  PDPT_ENTRY_2MB, *PPDPT_ENTRY_2MB;
static_assert(sizeof(PML4_ENTRY_2MB) == 8,
              "PML4_ENTRY_1GB Size Mismatch");

//
// See "2-Mbyte PDE-Long Mode".
//
typedef struct _PD_ENTRY_2MB
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT64 Valid : 1;               // [0]
            UINT64 Write : 1;               // [1]
            UINT64 User : 1;                // [2]
            UINT64 WriteThrough : 1;        // [3]
            UINT64 CacheDisable : 1;        // [4]
            UINT64 Accessed : 1;            // [5]
            UINT64 Dirty : 1;               // [6]
            UINT64 LargePage : 1;           // [7]
            UINT64 Global : 1;              // [8]
            UINT64 Avl : 3;                 // [9:11]
            UINT64 Pat : 1;                 // [12]
            UINT64 Reserved1 : 8;           // [13:20]
            UINT64 PageFrameNumber : 31;    // [21:51]
            UINT64 Reserved2 : 11;          // [52:62]
            UINT64 NoExecute : 1;           // [63]
        } Fields;
    };
} PD_ENTRY_2MB, *PPD_ENTRY_2MB;
static_assert(sizeof(PD_ENTRY_2MB) == 8,
              "PDE_ENTRY_2MB Size Mismatch");

//
// See "GDTR and IDTR Format-Long Mode"
//
#include <pshpack1.h>
typedef struct _DESCRIPTOR_TABLE_REGISTER
{
    UINT16 Limit;
    ULONG_PTR Base;
} DESCRIPTOR_TABLE_REGISTER, *PDESCRIPTOR_TABLE_REGISTER;
static_assert(sizeof(DESCRIPTOR_TABLE_REGISTER) == 10,
              "DESCRIPTOR_TABLE_REGISTER Size Mismatch");
#include <poppack.h>

//
// See "Long-Mode Segment Descriptors" and some of definitions
// (eg, "Code-Segment Descriptor-Long Mode")
//
typedef struct _SEGMENT_DESCRIPTOR
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT16 LimitLow;        // [0:15]
            UINT16 BaseLow;         // [16:31]
            UINT32 BaseMiddle : 8;  // [32:39]
            UINT32 Type : 4;        // [40:43]
            UINT32 System : 1;      // [44]
            UINT32 Dpl : 2;         // [45:46]
            UINT32 Present : 1;     // [47]
            UINT32 LimitHigh : 4;   // [48:51]
            UINT32 Avl : 1;         // [52]
            UINT32 LongMode : 1;    // [53]
            UINT32 DefaultBit : 1;  // [54]
            UINT32 Granularity : 1; // [55]
            UINT32 BaseHigh : 8;    // [56:63]
        } Fields;
    };
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;
static_assert(sizeof(SEGMENT_DESCRIPTOR) == 8,
              "SEGMENT_DESCRIPTOR Size Mismatch");

typedef struct _SEGMENT_ATTRIBUTE
{
    union
    {
        UINT16 AsUInt16;
        struct
        {
            UINT16 Type : 4;        // [0:3]
            UINT16 System : 1;      // [4]
            UINT16 Dpl : 2;         // [5:6]
            UINT16 Present : 1;     // [7]
            UINT16 Avl : 1;         // [8]
            UINT16 LongMode : 1;    // [9]
            UINT16 DefaultBit : 1;  // [10]
            UINT16 Granularity : 1; // [11]
            UINT16 Reserved1 : 4;   // [12:15]
        } Fields;
    };
} SEGMENT_ATTRIBUTE, *PSEGMENT_ATTRIBUTE;
static_assert(sizeof(SEGMENT_ATTRIBUTE) == 2,
              "SEGMENT_ATTRIBUTE Size Mismatch");

//
// hvsnap specific structures.
//

typedef struct _PML4E_TREE
{
    DECLSPEC_ALIGN(PAGE_SIZE) PDPT_ENTRY_2MB PdptEntries[512];
    DECLSPEC_ALIGN(PAGE_SIZE) PD_ENTRY_2MB PdEntries[512][512];
} PML4E_TREE, *PPML4E_TREE;

//
// A 4KB nested page table (512 leaf PTEs). Used to split a single 2MB PDE so a
// single 4KB page can be marked non-executable while its neighbours stay
// executable. The leaf entry layout matches PML4_ENTRY_2MB: the PageFrameNumber
// field spans [12:51] (a 4KB frame number) and there is a NoExecute bit [63],
// which is exactly what a 4KB leaf PTE needs.
//
typedef PML4_ENTRY_2MB PT_ENTRY_4KB, *PPT_ENTRY_4KB;

typedef struct _NESTED_PAGE_TABLE
{
    DECLSPEC_ALIGN(PAGE_SIZE) PT_ENTRY_4KB Entries[512];
} NESTED_PAGE_TABLE, *PNESTED_PAGE_TABLE;

typedef struct _SHARED_VIRTUAL_PROCESSOR_DATA
{
    PVOID MsrPermissionsMap;
    DECLSPEC_ALIGN(PAGE_SIZE) PML4_ENTRY_2MB Pml4Entries[512];
    DECLSPEC_ALIGN(PAGE_SIZE) PML4E_TREE Pml4eTrees[2];    // For 1TB
} SHARED_VIRTUAL_PROCESSOR_DATA, *PSHARED_VIRTUAL_PROCESSOR_DATA;

typedef struct _VIRTUAL_PROCESSOR_DATA
{
    union
    {
        //
        //  Low     HostStackLimit[0]                        StackLimit
        //  ^       ...
        //  ^       HostStackLimit[KERNEL_STACK_SIZE - 2]    StackBase
        //  High    HostStackLimit[KERNEL_STACK_SIZE - 1]    StackBase
        //
        DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStackLimit[KERNEL_STACK_SIZE];
        struct
        {
            UINT8 StackContents[KERNEL_STACK_SIZE - (sizeof(PVOID) * 8) - sizeof(KTRAP_FRAME)];
            KTRAP_FRAME TrapFrame;
            UINT64 GuestVmcbPa;     // HostRsp
            UINT64 HostVmcbPa;
            struct _VIRTUAL_PROCESSOR_DATA* Self;
            PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData;
            UINT64 Padding1;        // To keep HostRsp 16 bytes aligned
            UINT64 Reserved1;
            //
            // Guest CR8 (TPR) latched at #VMEXIT entry BEFORE the host raises
            // IRQL (KeRaiseIrqlToDpcLevel writes CR8), so a park on this exit
            // reports the guest's actual CR8 rather than the host
            // DISPATCH_LEVEL value. Per-exit; only meaningful for the exit
            // that parks. Lives in the stack layout (StackContents shrunk by
            // two pointer slots: this field plus an alignment pad, keeping
            // KTRAP_FRAME 16-byte aligned and the total size unchanged).
            //
            UINT64 GuestCr8AtExit;
            UINT64 Padding2;        // KTRAP_FRAME alignment keeper
        } HostStackLayout;
    };

    DECLSPEC_ALIGN(PAGE_SIZE) VMCB GuestVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB HostVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStateArea[PAGE_SIZE];
} VIRTUAL_PROCESSOR_DATA, *PVIRTUAL_PROCESSOR_DATA;
static_assert(sizeof(VIRTUAL_PROCESSOR_DATA) == KERNEL_STACK_SIZE + PAGE_SIZE * 3,
              "VIRTUAL_PROCESSOR_DATA Size Mismatch");

typedef struct _GUEST_REGISTERS
{
    UINT64 R15;
    UINT64 R14;
    UINT64 R13;
    UINT64 R12;
    UINT64 R11;
    UINT64 R10;
    UINT64 R9;
    UINT64 R8;
    UINT64 Rdi;
    UINT64 Rsi;
    UINT64 Rbp;
    UINT64 Rsp;
    UINT64 Rbx;
    UINT64 Rdx;
    UINT64 Rcx;
    UINT64 Rax;
} GUEST_REGISTERS, *PGUEST_REGISTERS;

typedef struct _GUEST_CONTEXT
{
    PGUEST_REGISTERS VpRegs;
    BOOLEAN ExitVm;
} GUEST_CONTEXT, *PGUEST_CONTEXT;


//
// x86-64 defined constants.
//
#define IA32_MSR_PAT    0x00000277
#define IA32_MSR_EFER   0xc0000080

#define EFER_SVME       (1UL << 12)

#define RPL_MASK        3
#define DPL_SYSTEM      0

#define CPUID_FN8000_0001_ECX_SVM                   (1UL << 2)
#define CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT    (1UL << 31)
#define CPUID_FN8000_000A_EDX_NP                    (1UL << 0)

#define CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING          0x00000000
#define CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS       0x00000001
#define CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX    0x80000001
#define CPUID_SVM_FEATURES                                      0x8000000a
//
// The Microsoft Hypervisor interface defined constants.
//
#define CPUID_HV_VENDOR_AND_MAX_FUNCTIONS   0x40000000
#define CPUID_HV_INTERFACE                  0x40000001

//
// hvsnap specific constants.
//
#define CPUID_UNLOAD_SIMPLE_SVM     0x41414141
#define CPUID_HV_MAX                CPUID_HV_INTERFACE

//
// RETIRED: the four magic leaves below (nested-TLB flush, cloak on/off,
// presence probe) are no longer referenced -- the control signals moved to the
// VMMCALL bridge (see the VMMCALL request kinds below) when CPUID passthrough
// became total for stealth. The values are kept for history/wire compatibility.
//
// Magic CPUID leaf used internally to flush the nested TLB on a specific
// processor. 'HVTF' in ASCII.
//
#define CPUID_HVSNAP_FLUSH_TLB     0x48565446

//
// Magic CPUID leaves used internally to enable/disable
// the per-core RDTSC/RDTSCP intercept for TSC cloaking (feature #2). 'HVTG' /
// 'HVTH' in ASCII.
//
#define CPUID_HVSNAP_CLOAK_ON      0x48565447
#define CPUID_HVSNAP_CLOAK_OFF     0x48565448

//
// Private "am I virtualized?" leaf ('HVTI'). Deliberately NOT a standard
// hypervisor leaf (0x40000000), so the guest cannot use it to detect us.
//
#define CPUID_HVSNAP_PRESENT       0x48565449

//
// VMMCALL request kinds. Since CPUID is passed through natively (not
// intercepted) for stealth, the guest->host control bridge is now VMMCALL. The
// caller (guest kernel) sets its per-CPU slot g_VmmcallReq[cpu] and executes
// SvVmmcall(); the #VMEXIT handler reads the slot. VMMCALL from user mode, or
// with no pending request, is reflected back as #UD (looks unsupported), so a
// probe cannot use it to detect the hypervisor.
//
#define HVREQ_NONE          0
#define HVREQ_FLUSH_TLB     1
#define HVREQ_CLOAK_ON      2
#define HVREQ_CLOAK_OFF     3
#define HVREQ_UNLOAD        4

//
// SvVmmcall (x64.asm): execute VMMCALL, storing EAX/EBX/ECX/EDX into Out[4].
//
EXTERN_C VOID SvVmmcall(_Out_writes_(4) unsigned int* Out);

//
// IA32_TSC_AUX - returned in ECX by RDTSCP (processor id). Read from the host
// MSR so the emulated RDTSC/RDTSCP reports the same value the guest expects.
//
#define IA32_MSR_TSC_AUX            0xc0000103

//
// AMD VMCB TLB_CONTROL: flush the entire TLB (all ASIDs) on the next VMRUN.
// See "TLB Control" in the APM.
//
#define SVM_TLB_CONTROL_FLUSH_ALL   1

/*!
    @brief      Breaks into a kernel debugger when it is present.

    @details    This macro is emits software breakpoint that only hits when a
                kernel debugger is present. This macro is useful because it does
                not change the current frame unlike the DbgBreakPoint function,
                and breakpoint by this macro can be overwritten with NOP without
                impacting other breakpoints.
 */
#define SV_DEBUG_BREAK() \
    if (KD_DEBUGGER_NOT_PRESENT) \
    { \
        NOTHING; \
    } \
    else \
    { \
        __debugbreak(); \
    } \
    reinterpret_cast<void*>(0)

//
// A power state callback handle.
//
static PVOID g_PowerCallbackRegistration;

//
// The IOCTL control device object (\Device\hvsnap).
//
static PDEVICE_OBJECT g_DeviceObject;

//
// The current freeze-at-RIP target session. Populated by HVSNAP_IOCTL_ARM,
// consulted from the #BP #VMEXIT handler (any processor, elevated IRQL). The
// controller identifies the target in user mode and writes the INT3; the driver
// only matches PID + RIP and parks the hitting thread on the pre-allocated stub.
//
// Field access rules: 64-bit fields are only written under ARM (while Active==0
// from the consumer's perspective) and read after Active is observed non-zero,
// so aligned 64-bit reads/writes are atomic on x64 and need no lock. Active/Hit
// are manipulated with Interlocked* and act as the publish/consume barriers.
//
typedef struct _HVSNAP_TARGET
{
    volatile LONG  Active;          // set by ARM, cleared by DISARM
    volatile LONG  Hit;             // set once the first target thread parks
    volatile LONG64 ParkedCount;    // number of target threads redirected to the stub
    UINT64 TargetPid;               // watched process id
    UINT64 TargetRip;               // absolute VA to trap on (guest virtual)
    UINT64 ParkStubVa;              // VA of the "jmp $" stub in the target
    volatile UINT64 HitTid;         // thread id of the first thread to hit

    //
    // NPT execute-trap bookkeeping (populated by SvArmNptTrap under the ARM
    // IOCTL at PASSIVE_LEVEL; consulted from the #NPF handler).
    //
    UINT64 TargetCr3;               // target process CR3 (DirectoryTableBase) for gating
    UINT64 TargetGpa;              // page-aligned guest-physical addr of the target page
    ULONG  PtIndex;                 // index of the target 4KB leaf within the split table
    PPD_ENTRY_2MB Pde;              // the 2MB PDE we split (to restore on disarm)
    PD_ENTRY_2MB SavedPde;          // original 2MB PDE contents
    PNESTED_PAGE_TABLE SplitTable;  // the 4KB page table we allocated for the split
    PMDL LockedMdl;                 // MDL pinning the target page (guest-physical stable)
    PEPROCESS TargetProcess;        // referenced target process
    volatile LONG NptArmed;         // NPT trap installed (split done)

    //
    // Conditional trigger (feature #1). Evaluated in the #NPF handler when the
    // target RIP is reached; a non-match steps over and keeps waiting.
    //
    HVSNAP_PREDICATE Predicate;    // Kind=NONE => park on first hit (unchanged)
    UINT64 HitSkip;                 // skip this many matches before parking
    volatile LONG64 MatchCount;     // predicate matches so far (diagnostic + skip counter)

    //
    // TSC cloak (feature #2). When active, the target's RDTSC/RDTSCP are
    // intercepted (CR3-gated) and reduced by StolenTsc so the wall-clock gap of
    // a freeze is invisible to the target's own timing checks. Other processes
    // pass through unchanged.
    //
    volatile LONG CloakActive;      // RDTSC/RDTSCP intercept installed + gating
    volatile LONG64 StolenTsc;      // cycles subtracted from the target's TSC reads
    volatile LONG64 ParkTsc;        // host TSC captured when the target parked

    //
    // Claimed-versus-ready publication: Hit is the CLAIM (first-hitter won
    // the CAS); HitReady is published only after the entire Hit* payload is
    // written and barriered. QUERY reports HitReady so the controller can
    // never observe partially initialized appended state.
    //
    volatile LONG HitReady;

    //
    // MEASURED segment bases of the first hitting thread, read from the VMCB
    // state-save area at the exact target RIP (park event). Published together
    // with HitTid; consumed via HVSNAP_STATE so the snapshot path records
    // measured values instead of OS-convention assumptions.
    //
    volatile UINT64 HitFsBase;
    volatile UINT64 HitGsBase;

    //
    // MEASURED control registers of the same park event, from the VMCB
    // state-save area (user mode cannot observe these). CR3/CR4/EFER are
    // live save-area fields; CR0 is kept current in the save area by the
    // VMSAVE/VMLOAD pairing; CR2 is the last-intercepted fault address.
    //
    volatile UINT64 HitCr0;
    volatile UINT64 HitCr2;
    volatile UINT64 HitCr3;
    volatile UINT64 HitCr4;
    volatile UINT64 HitEfer;

    //
    // MEASURED same-hit VMCB state-save extras: guest DR6/DR7 (distinct from
    // the user-mode thread-context view), syscall/sysenter configuration,
    // CPL, PAT, DEBUG_CTL (LBR/ freeze-on-branch config).
    //
    volatile UINT64 HitDr6;
    volatile UINT64 HitDr7;
    volatile UINT64 HitStar;
    volatile UINT64 HitLStar;
    volatile UINT64 HitCStar;
    volatile UINT64 HitSfMask;
    volatile UINT64 HitKernelGsBase;
    volatile UINT64 HitSysenterCs;
    volatile UINT64 HitSysenterEsp;
    volatile UINT64 HitSysenterEip;
    volatile UINT64 HitCpl;
    volatile UINT64 HitGPat;
    volatile UINT64 HitDbgCtl;

    //
    // Timing and per-thread MSR state of the same park event: guest-VISIBLE
    // TSC (park host TSC minus cycles already cloaked away) and TSC_AUX
    // (MSR 0xC0000103 read in the exit context where the guest's value is
    // still resident - the same read the RDTSCP intercept uses).
    //
    volatile UINT64 HitTscGuest;
    volatile UINT64 HitTscAux;

    //
    // Guest CR8 (TPR) latched at exit entry before the host IRQL raise (see
    // VIRTUAL_PROCESSOR_DATA::GuestCr8AtExit). Same-hit guest value, never
    // the host DISPATCH_LEVEL CR8.
    //
    volatile UINT64 HitCr8;

    //
    // MEASURED descriptor-table registers of the same park event, from the
    // VMCB state-save area (SVM carries the full descriptor cache, including
    // the hidden LDTR/TR base/limit/attributes): what SGDT/SIDT/SLDT/STR
    // would have returned had the target executed them at the frozen
    // instruction. v3 tier - older controllers never receive these (QUERY
    // gates on HVSNAP_STATE_V2_SIZE / sizeof(HVSNAP_STATE) independently).
    //
    volatile UINT64 HitGdtrBase;
    volatile UINT64 HitIdtrBase;
    volatile UINT64 HitLdtrBase;
    volatile UINT64 HitTrBase;
    volatile UINT32 HitGdtrLimit;
    volatile UINT32 HitIdtrLimit;
    volatile UINT32 HitLdtrLimit;
    volatile UINT32 HitTrLimit;
    volatile UINT32 HitLdtrAttrib;
    volatile UINT32 HitTrAttrib;
    volatile UINT16 HitLdtrSelector;
    volatile UINT16 HitTrSelector;
} HVSNAP_TARGET;

static HVSNAP_TARGET g_Target;

//
// RECHECK serialization (Stage A VA-trap fix): one re-resolve at a time.
//
static volatile LONG g_RecheckBusy = 0;

//
// Register-trace ring (feature: register trace). When Enabled, the #NPF handler
// captures a record per matching hit into Ring[WriteIndex % Capacity] and keeps
// running (no freeze). WriteIndex is a lock-free multi-producer reservation
// counter; ReadIndex is advanced only by the TRACE_DRAIN handler (PASSIVE).
//
typedef struct _HVSNAP_TRACE
{
    volatile LONG   Enabled;        // capture active
    PHVSNAP_RECORD Ring;           // non-paged record array
    UINT64          Capacity;       // number of record slots
    SIZE_T          RingBytes;      // allocation size
    volatile LONG64 WriteIndex;     // total records reserved (producer)
    LONG64          ReadIndex;      // next record to drain (consumer / DRAIN ioctl)
    volatile LONG64 DropCount;      // records overwritten before being drained
} HVSNAP_TRACE;

static HVSNAP_TRACE g_Trace;

#define HVSNAP_TRACE_POOL_TAG  'rtvh'

//
// Per-processor state for the single-step-over dance. When the #NPF handler
// needs to let a non-target instruction on the trapped page execute, it makes
// the leaf executable and single-steps (guest RFLAGS.TF); the resulting #DB is
// caught and the leaf is re-armed. Indexed by KeGetCurrentProcessorNumberEx.
// Kept out of VIRTUAL_PROCESSOR_DATA because that structure's size is asserted
// and its layout is shared with x64.asm.
//
#define HVSNAP_MAX_PROCESSORS  256

typedef struct _HVSNAP_STEP_STATE
{
    BOOLEAN Stepping;               // a single-step-over is in progress on this core
    BOOLEAN GuestTfWasSet;          // the guest already had RFLAGS.TF before we set it
} HVSNAP_STEP_STATE;

static HVSNAP_STEP_STATE g_StepState[HVSNAP_MAX_PROCESSORS];

//
// Per-CPU VMMCALL request slot (set by the guest just before SvVmmcall).
//
static volatile LONG g_VmmcallReq[HVSNAP_MAX_PROCESSORS];

//
// Per-CPU "this processor has been virtualized" flag. Replaces the old
// CPUID-based self-check now that CPUID is not intercepted: set to 1 right
// before VMRUN, so after the processor resumes as the guest the two-pass
// RtlCaptureContext trick reads 1 and stops re-virtualizing.
//
static volatile LONG g_CpuVirtualized[HVSNAP_MAX_PROCESSORS];

//
// Global pointer to the shared per-guest data that holds the nested page tables.
// Set once virtualization is up (SvVirtualizeAllProcessors) so the ARM/DISARM
// paths can edit the NPT from an arbitrary thread context. Cleared when freed.
//
static PSHARED_VIRTUAL_PROCESSOR_DATA g_SharedVpData;

/*!
    @brief      Sends a message to the kernel debugger.

    @param[in]  Format - The format string to print.
 */
#pragma prefast(push)
#pragma prefast(disable : 26826, "C-style variable arguments needed for DbgPrint.")
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
static
VOID
SvDebugPrint (
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    )
{
    va_list argList;

    va_start(argList, Format);
    vDbgPrintExWithPrefix("[hvsnap] ",
                          DPFLTR_IHVDRIVER_ID,
                          DPFLTR_ERROR_LEVEL,
                          Format,
                          argList);
    va_end(argList);
}
#pragma prefast(pop)

/*!
    @brief      Allocates page aligned, zero filled physical memory.

    @details    This function allocates page aligned nonpaged pool. The
                allocated memory is zero filled and must be freed with
                SvFreePageAlingedPhysicalMemory. On Windows 8 and later versions
                of Windows, the allocated memory is non executable.

    @param[in]  NumberOfBytes - A size of memory to allocate in byte. This must
                be equal or greater than PAGE_SIZE.

    @result     A pointer to the allocated memory filled with zero; or NULL when
                there is insufficient memory to allocate requested size.
 */
__drv_allocatesMem(Mem)
_Post_writable_byte_size_(NumberOfBytes)
_Post_maybenull_
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
_Must_inspect_result_
static
PVOID
SvAllocatePageAlingedPhysicalMemory (
    _In_ SIZE_T NumberOfBytes
    )
{
    PVOID memory;

    //
    // The size must be equal or greater than PAGE_SIZE in order to allocate
    // page aligned memory.
    //
    NT_ASSERT(NumberOfBytes >= PAGE_SIZE);

    memory = ExAllocatePool2(POOL_FLAG_NON_PAGED, NumberOfBytes, 'rtvh');
    if (memory != nullptr)
    {
        NT_ASSERT(PAGE_ALIGN(memory) == memory);
        RtlZeroMemory(memory, NumberOfBytes);
    }
    return memory;
}

/*!
    @brief      Frees memory allocated by SvAllocatePageAlingedPhysicalMemory.

    @param[in]  BaseAddress - The address returned by
                SvAllocatePageAlingedPhysicalMemory.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
static
VOID
SvFreePageAlingedPhysicalMemory (
    _Pre_notnull_ __drv_freesMem(Mem) PVOID BaseAddress
    )
{
    ExFreePoolWithTag(BaseAddress, 'rtvh');
}

/*!
    @brief      Allocates page aligned, zero filled contiguous physical memory.

    @details    This function allocates page aligned nonpaged pool where backed
                by contiguous physical pages. The allocated memory is zero
                filled and must be freed with SvFreeContiguousMemory. The
                allocated memory is executable.

    @param[in]  NumberOfBytes - A size of memory to allocate in byte.

    @result     A pointer to the allocated memory filled with zero; or NULL when
                there is insufficient memory to allocate requested size.
 */
_Post_writable_byte_size_(NumberOfBytes)
_Post_maybenull_
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
_Must_inspect_result_
static
PVOID
SvAllocateContiguousMemory (
    _In_ SIZE_T NumberOfBytes
    )
{
    PVOID memory;
    PHYSICAL_ADDRESS boundary, lowest, highest;

    boundary.QuadPart = lowest.QuadPart = 0;
    highest.QuadPart = -1;

    memory = MmAllocateContiguousNodeMemory(NumberOfBytes,
                                            lowest,
                                            highest,
                                            boundary,
                                            PAGE_READWRITE,
                                            MM_ANY_NODE_OK);
    if (memory != nullptr)
    {
        RtlZeroMemory(memory, NumberOfBytes);
    }
    return memory;
}

/*!
    @brief      Frees memory allocated by SvAllocateContiguousMemory.

    @param[in]  BaseAddress - The address returned by SvAllocateContiguousMemory.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
static
VOID
SvFreeContiguousMemory (
    _In_ PVOID BaseAddress
    )
{
    MmFreeContiguousMemory(BaseAddress);
}

/*!
    @brief          Injects #GP with 0 of error code.

    @param[in,out]  VpData - Per processor data.
 */
_IRQL_requires_same_
static
VOID
SvInjectGeneralProtectionException (
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
    )
{
    EVENTINJ event;

    //
    // Inject #GP(vector = 13, type = 3 = exception) with a valid error code.
    // An error code are always zero. See "#GP-General-Protection Exception
    // (Vector 13)" for details about the error code.
    //
    event.AsUInt64 = 0;
    event.Fields.Vector = 13;
    event.Fields.Type = 3;
    event.Fields.ErrorCodeValid = 1;
    event.Fields.Valid = 1;
    VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}

//
// RFLAGS.TF (trap flag) - single-step.
//
#define RFLAGS_TF   (1UL << 8)

/*!
    @brief          Re-injects a #DB (debug) exception into the guest.

    @details        Used when an intercepted #DB is not one of our single-step
                    traps (i.e., it belongs to the guest's own debugging).

    @param[in,out]  VpData - Per processor data.
 */
_IRQL_requires_same_
static
VOID
SvInjectDebugException (
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
    )
{
    EVENTINJ event;

    event.AsUInt64 = 0;
    event.Fields.Vector = 1;    // #DB
    event.Fields.Type = 3;      // exception
    event.Fields.Valid = 1;
    VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}

/*!
    @brief          Reads a guest general-purpose register by x86 encoding index.

    @details        RAX and RSP live in the VMCB state-save area (authoritative);
                    the other 14 GPRs are in the pushed guest-register block.

    @param[in]      VpData - Per processor data (VMCB state-save area).
    @param[in]      Regs   - Pushed guest GPRs.
    @param[in]      Index  - 0 rax,1 rcx,2 rdx,3 rbx,4 rsp,5 rbp,6 rsi,7 rdi,8..15 r8..r15.

    @result         The 64-bit register value.
 */
_IRQL_requires_same_
static
UINT64
SvReadGuestGpr (
    _In_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ PGUEST_REGISTERS Regs,
    _In_ ULONG Index
    )
{
    switch (Index & 0xF)
    {
    case 0:  return VpData->GuestVmcb.StateSaveArea.Rax;
    case 1:  return Regs->Rcx;
    case 2:  return Regs->Rdx;
    case 3:  return Regs->Rbx;
    case 4:  return VpData->GuestVmcb.StateSaveArea.Rsp;
    case 5:  return Regs->Rbp;
    case 6:  return Regs->Rsi;
    case 7:  return Regs->Rdi;
    case 8:  return Regs->R8;
    case 9:  return Regs->R9;
    case 10: return Regs->R10;
    case 11: return Regs->R11;
    case 12: return Regs->R12;
    case 13: return Regs->R13;
    case 14: return Regs->R14;
    default: return Regs->R15;   // 15
    }
}

/*!
    @brief          Evaluates the armed conditional trigger against guest state.

    @details        Kind=NONE always matches (legacy "park on first hit"). For a
                    register predicate, reads the selected GPR, truncates to the
                    requested width, applies the AND-mask, and compares (unsigned)
                    against the immediate.

    @param[in]      VpData - Per processor data.
    @param[in]      Regs   - Pushed guest GPRs.

    @result         TRUE if the predicate matches (this hit should count).
 */
_IRQL_requires_same_
static
BOOLEAN
SvEvaluatePredicate (
    _In_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ PGUEST_REGISTERS Regs
    )
{
    UINT64 value;
    UINT64 mask;
    UINT64 imm;
    UINT64 widthMask;
    ULONG size;

    if (g_Target.Predicate.Kind == HVSNAP_PRED_NONE)
    {
        return TRUE;
    }
    if (g_Target.Predicate.Kind != HVSNAP_PRED_REG)
    {
        //
        // Unknown predicate kind - fail safe by matching (behaves like NONE)
        // rather than silently never firing.
        //
        return TRUE;
    }

    size = g_Target.Predicate.Size;
    widthMask = (size == 0 || size >= 8) ? ~0ULL
                                         : ((1ULL << (size * 8)) - 1ULL);
    mask = (g_Target.Predicate.Mask != 0) ? g_Target.Predicate.Mask : ~0ULL;

    value = SvReadGuestGpr(VpData, Regs, g_Target.Predicate.Reg) & widthMask;
    value &= mask;
    imm = g_Target.Predicate.Imm & widthMask;

    switch (g_Target.Predicate.Op)
    {
    case HVSNAP_OP_EQ:  return (value == imm);
    case HVSNAP_OP_NE:  return (value != imm);
    case HVSNAP_OP_ULT: return (value <  imm);
    case HVSNAP_OP_UGT: return (value >  imm);
    case HVSNAP_OP_ULE: return (value <= imm);
    case HVSNAP_OP_UGE: return (value >= imm);
    default:             return TRUE;
    }
}

/*!
    @brief          Captures one register sample into the trace ring (feature:
                    register trace). Lock-free multi-producer: reserve a slot via
                    InterlockedIncrement, fill it, then publish by writing HitIndex
                    last. The drain side validates a slot by HitIndex == its index.

    @param[in]      VpData - Per processor data (VMCB save area).
    @param[in]      Regs   - Pushed guest GPRs.
 */
_IRQL_requires_same_
static
VOID
SvTraceCapture (
    _In_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ PGUEST_REGISTERS Regs
    )
{
    LONG64 idx;
    PHVSNAP_RECORD rec;

    if (g_Trace.Ring == nullptr || g_Trace.Capacity == 0)
    {
        return;
    }

    idx = InterlockedIncrement64(&g_Trace.WriteIndex) - 1;
    rec = &g_Trace.Ring[static_cast<UINT64>(idx) % g_Trace.Capacity];

    rec->Rax = VpData->GuestVmcb.StateSaveArea.Rax;   // RAX/RSP authoritative in VMCB
    rec->Rcx = Regs->Rcx;
    rec->Rdx = Regs->Rdx;
    rec->Rbx = Regs->Rbx;
    rec->Rsp = VpData->GuestVmcb.StateSaveArea.Rsp;
    rec->Rbp = Regs->Rbp;
    rec->Rsi = Regs->Rsi;
    rec->Rdi = Regs->Rdi;
    rec->R8  = Regs->R8;
    rec->R9  = Regs->R9;
    rec->R10 = Regs->R10;
    rec->R11 = Regs->R11;
    rec->R12 = Regs->R12;
    rec->R13 = Regs->R13;
    rec->R14 = Regs->R14;
    rec->R15 = Regs->R15;
    rec->Rip = VpData->GuestVmcb.StateSaveArea.Rip;
    rec->Rflags = VpData->GuestVmcb.StateSaveArea.Rflags;
    rec->Cr3 = VpData->GuestVmcb.StateSaveArea.Cr3;
    rec->FsBase = VpData->GuestVmcb.StateSaveArea.FsBase;
    rec->GsBase = VpData->GuestVmcb.StateSaveArea.GsBase;
    rec->Cs = VpData->GuestVmcb.StateSaveArea.CsSelector;
    rec->Ss = VpData->GuestVmcb.StateSaveArea.SsSelector;
    rec->Ds = VpData->GuestVmcb.StateSaveArea.DsSelector;
    rec->Es = VpData->GuestVmcb.StateSaveArea.EsSelector;
    rec->Fs = VpData->GuestVmcb.StateSaveArea.FsSelector;
    rec->Gs = VpData->GuestVmcb.StateSaveArea.GsSelector;
    rec->Pad = 0;

    KeMemoryBarrier();                          // body visible before the marker
    rec->HitIndex = static_cast<UINT64>(idx);   // publish
}

/*!
    @brief          Parks the current guest thread on the park stub.

    @details        Redirects the guest RIP to the controller-allocated "jmp $"
                    stub so the thread spins harmlessly in user mode and can be
                    suspended cleanly by the controller. Records the first hitter.

    @param[in,out]  VpData - Per processor data.
 */
_IRQL_requires_same_
static
VOID
SvParkTargetThread (
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
    )
{
    VpData->GuestVmcb.StateSaveArea.Rip = g_Target.ParkStubVa;
    InterlockedIncrement64(&g_Target.ParkedCount);

    if (InterlockedCompareExchange(&g_Target.Hit, 1, 0) == 0)
    {
        //
        // First thread to freeze. Capture the host TSC now so DISARM can measure
        // the freeze duration and fold it into StolenTsc (TSC cloak, feature #2).
        //
        InterlockedExchange64(&g_Target.ParkTsc, static_cast<LONG64>(__rdtsc()));
        //
        // Full same-hit payload from the VMCB state-save area of THIS thread
        // at THIS event (the trap fired before the instruction ran, so these
        // are the values the target instruction will observe), plus the
        // exit-entry guest CR8 latch and the still-resident TSC_AUX.
        //
        g_Target.HitFsBase = VpData->GuestVmcb.StateSaveArea.FsBase;
        g_Target.HitGsBase = VpData->GuestVmcb.StateSaveArea.GsBase;
        g_Target.HitCr0 = VpData->GuestVmcb.StateSaveArea.Cr0;
        g_Target.HitCr2 = VpData->GuestVmcb.StateSaveArea.Cr2;
        g_Target.HitCr3 = VpData->GuestVmcb.StateSaveArea.Cr3;
        g_Target.HitCr4 = VpData->GuestVmcb.StateSaveArea.Cr4;
        g_Target.HitEfer = VpData->GuestVmcb.StateSaveArea.Efer;
        g_Target.HitDr6 = VpData->GuestVmcb.StateSaveArea.Dr6;
        g_Target.HitDr7 = VpData->GuestVmcb.StateSaveArea.Dr7;
        g_Target.HitStar = VpData->GuestVmcb.StateSaveArea.Star;
        g_Target.HitLStar = VpData->GuestVmcb.StateSaveArea.LStar;
        g_Target.HitCStar = VpData->GuestVmcb.StateSaveArea.CStar;
        g_Target.HitSfMask = VpData->GuestVmcb.StateSaveArea.SfMask;
        g_Target.HitKernelGsBase = VpData->GuestVmcb.StateSaveArea.KernelGsBase;
        g_Target.HitSysenterCs = VpData->GuestVmcb.StateSaveArea.SysenterCs;
        g_Target.HitSysenterEsp = VpData->GuestVmcb.StateSaveArea.SysenterEsp;
        g_Target.HitSysenterEip = VpData->GuestVmcb.StateSaveArea.SysenterEip;
        g_Target.HitCpl = VpData->GuestVmcb.StateSaveArea.Cpl;
        g_Target.HitGPat = VpData->GuestVmcb.StateSaveArea.GPat;
        g_Target.HitDbgCtl = VpData->GuestVmcb.StateSaveArea.DbgCtl;
        g_Target.HitCr8 = VpData->HostStackLayout.GuestCr8AtExit;
        //
        // v3 tier: descriptor-table registers (the VMCB keeps the full
        // descriptor cache, so the hidden LDTR/TR fields are measured too,
        // not just the architecturally visible selector/base/limit).
        //
        g_Target.HitGdtrBase = VpData->GuestVmcb.StateSaveArea.GdtrBase;
        g_Target.HitIdtrBase = VpData->GuestVmcb.StateSaveArea.IdtrBase;
        g_Target.HitLdtrBase = VpData->GuestVmcb.StateSaveArea.LdtrBase;
        g_Target.HitTrBase = VpData->GuestVmcb.StateSaveArea.TrBase;
        g_Target.HitGdtrLimit = VpData->GuestVmcb.StateSaveArea.GdtrLimit;
        g_Target.HitIdtrLimit = VpData->GuestVmcb.StateSaveArea.IdtrLimit;
        g_Target.HitLdtrLimit = VpData->GuestVmcb.StateSaveArea.LdtrLimit;
        g_Target.HitTrLimit = VpData->GuestVmcb.StateSaveArea.TrLimit;
        g_Target.HitLdtrAttrib = VpData->GuestVmcb.StateSaveArea.LdtrAttrib;
        g_Target.HitTrAttrib = VpData->GuestVmcb.StateSaveArea.TrAttrib;
        g_Target.HitLdtrSelector = VpData->GuestVmcb.StateSaveArea.LdtrSelector;
        g_Target.HitTrSelector = VpData->GuestVmcb.StateSaveArea.TrSelector;
        //
        // Guest-VISIBLE TSC: the park host TSC minus the cycles the cloak has
        // already subtracted (what the target's next RDTSC would return).
        //
        g_Target.HitTscGuest = static_cast<UINT64>(
            static_cast<LONG64>(g_Target.ParkTsc) - g_Target.StolenTsc);
        g_Target.HitTscAux = __readmsr(IA32_MSR_TSC_AUX);
        g_Target.HitTid = reinterpret_cast<UINT64>(PsGetCurrentThreadId());
        //
        // Claimed-versus-ready publication: the CAS above claimed the slot;
        // publish the READY flag only after the whole payload is written.
        // QUERY reports HitReady, never the bare claim, so the controller
        // cannot observe partially initialized appended state.
        //
        KeMemoryBarrier();
        InterlockedExchange(&g_Target.HitReady, 1);
        SvDebugPrint("HIT: pid=%llu rip=0x%llx tid=%llu -> parked at 0x%llx\n",
                     g_Target.TargetPid,
                     g_Target.TargetRip,
                     g_Target.HitTid,
                     g_Target.ParkStubVa);
    }
}

/*!
    @brief          Handles #VMEXIT due to a nested page fault (#NPF).

    @details        The freeze-at-RIP trigger. The target 4KB nested page is
                    marked No-Execute, so any instruction FETCH from it faults
                    here (reads/writes still succeed - guest self-checksums pass).

                    On a fetch of the target page:
                      - If RIP == target and CR3 == target process: PARK.
                      - Otherwise a non-target instruction on the same page is
                        about to run: make the leaf executable and single-step
                        one instruction (RFLAGS.TF), then re-arm in the #DB
                        handler. NX is re-armed after every step, so the target
                        RIP always faults before it can execute (self-correcting).

    @param[in,out]  VpData - Per processor data.

    @result         TRUE if handled; FALSE if the fault was not ours (fatal).
 */
_IRQL_requires_same_
static
BOOLEAN
SvHandleNestedPageFault (
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ PGUEST_REGISTERS Regs
    )
{
    UINT64 faultGpa;
    UINT64 pageBase;
    UINT64 guestRip;
    UINT64 guestCr3;
    ULONG processorIndex;
    BOOLEAN parkNow;

    if (InterlockedCompareExchange(&g_Target.NptArmed, 1, 1) == 0)
    {
        //
        // No NPT trap installed - we should not be receiving #NPF (the map is a
        // full identity map). Not ours.
        //
        return FALSE;
    }

    faultGpa = VpData->GuestVmcb.ControlArea.ExitInfo2;
    pageBase = faultGpa & ~(static_cast<UINT64>(PAGE_SIZE) - 1);
    if (pageBase != g_Target.TargetGpa)
    {
        //
        // A fault on some other page - not ours (should not happen).
        //
        return FALSE;
    }

    guestRip = VpData->GuestVmcb.StateSaveArea.Rip;
    guestCr3 = VpData->GuestVmcb.StateSaveArea.Cr3;
    processorIndex = KeGetCurrentProcessorNumberEx(nullptr);

    parkNow = FALSE;
    if ((guestRip == g_Target.TargetRip) &&
        ((guestCr3 & ~0xFFFULL) == (g_Target.TargetCr3 & ~0xFFFULL)))
    {
        //
        // Our target instruction in our target process. Evaluate the conditional
        // trigger; only a match qualifies. In TRACE mode a match captures a
        // register sample and continues (never parks). In freeze mode a match
        // past any skip count parks. Either way a non-match / trace-capture
        // falls through to the step-over path so this invocation runs.
        //
        if (SvEvaluatePredicate(VpData, Regs) != FALSE)
        {
            if (InterlockedCompareExchange(&g_Trace.Enabled, 1, 1) != 0)
            {
                SvTraceCapture(VpData, Regs);
            }
            else
            {
                LONG64 matches = InterlockedIncrement64(&g_Target.MatchCount);
                if (matches > static_cast<LONG64>(g_Target.HitSkip))
                {
                    parkNow = TRUE;
                }
            }
        }
    }

    if (parkNow != FALSE)
    {
        //
        // Park it. RIP now points at the stub (a different, executable page) so
        // it will not fault again. Leave the NPT armed for any sibling threads.
        //
        SvParkTargetThread(VpData);
        return TRUE;
    }

    //
    // Either a non-target instruction on the trapped page (or a different
    // process using the same physical page), or our target RIP whose predicate
    // did not match / is still being skipped. Let exactly one instruction
    // execute, then re-arm.
    //
    if (processorIndex < HVSNAP_MAX_PROCESSORS)
    {
        g_Target.SplitTable->Entries[g_Target.PtIndex].Fields.NoExecute = 0;
        g_StepState[processorIndex].GuestTfWasSet =
            ((VpData->GuestVmcb.StateSaveArea.Rflags & RFLAGS_TF) != 0);
        VpData->GuestVmcb.StateSaveArea.Rflags |= RFLAGS_TF;
        g_StepState[processorIndex].Stepping = TRUE;

        //
        // Enter an interrupt shadow for the single step so NO interrupt is taken
        // before the stepped instruction retires. Without this, a maskable
        // interrupt can preempt right after the instruction and reschedule the
        // thread onto another core BEFORE the #DB is delivered; the #DB then
        // lands where g_StepState[core].Stepping is FALSE and gets reflected to
        // the guest as a spurious #DB (STATUS_SINGLE_STEP crash). The shadow
        // guarantees the #DB is delivered on this same core. (Auto-clears after
        // one instruction.)
        //
        VpData->GuestVmcb.ControlArea.InterruptShadow |= 1ULL;

        //
        // Flush this core's nested TLB so the now-executable leaf takes effect.
        // Do not advance RIP: re-execute the faulting instruction (now allowed).
        //
        VpData->GuestVmcb.ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_ALL;
    }
    return TRUE;
}

/*!
    @brief          Handles #VMEXIT due to a #DB (debug) exception.

    @details        If this core is mid single-step-over (started by the #NPF
                    handler), re-arm the No-Execute leaf, restore the trap flag,
                    and continue. Otherwise the #DB belongs to the guest and is
                    reflected back.

    @param[in,out]  VpData - Per processor data.
 */
_IRQL_requires_same_
static
VOID
SvHandleDebugException (
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
    )
{
    ULONG processorIndex;

    processorIndex = KeGetCurrentProcessorNumberEx(nullptr);

    if ((processorIndex < HVSNAP_MAX_PROCESSORS) &&
        (g_StepState[processorIndex].Stepping != FALSE))
    {
        //
        // Completed one instruction. Re-arm the trap and stop single-stepping.
        // Review fix (2): the RECHECK move keeps SplitTable non-null, but a
        // disarm or a failed move can land here first — null/arm check
        // before touching the table. Review-2 fix (3): clear our TF on the
        // bail-out too (a stray single-step otherwise stays armed in the
        // guest), and read the table through one local.
        //
        if (g_StepState[processorIndex].GuestTfWasSet == FALSE)
        {
            VpData->GuestVmcb.StateSaveArea.Rflags &= ~static_cast<UINT64>(RFLAGS_TF);
        }
        if (InterlockedCompareExchange(&g_Target.NptArmed, 1, 1) == 0 ||
            g_Target.SplitTable == nullptr)
        {
            g_StepState[processorIndex].Stepping = FALSE;
            VpData->GuestVmcb.ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_ALL;
            return;
        }
        {
            PNESTED_PAGE_TABLE table = g_Target.SplitTable;
            const ULONG leaf = g_Target.PtIndex;
            table->Entries[leaf].Fields.NoExecute = 1;
        }
        g_StepState[processorIndex].Stepping = FALSE;
        VpData->GuestVmcb.ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_ALL;
    }
    else
    {
        //
        // Not our single-step - reflect the debug exception to the guest.
        //
        SvInjectDebugException(VpData);
    }
}

/*!
    @brief          Issues a VMMCALL guest->host request on the current CPU.

    @details        Sets this CPU's request slot, then executes VMMCALL, which
                    #VMEXITs into SvHandleVmmcall (CPUID is no longer intercepted).

    @param[in]      Req - one of HVREQ_*.
 */
_IRQL_requires_same_
static
VOID
SvIssueVmmcall (
    _In_ LONG Req
    )
{
    ULONG cpu;
    unsigned int out[4];

    cpu = KeGetCurrentProcessorNumberEx(nullptr);
    if (cpu >= HVSNAP_MAX_PROCESSORS)
    {
        return;     // not possible on supported hardware
    }
    g_VmmcallReq[cpu] = Req;
    SvVmmcall(out);
}

/*!
    @brief          KeIpiGenericCall worker: forces a nested-TLB flush on the
                    executing processor via a VMMCALL. Runs at IPI_LEVEL on every
                    processor via KeIpiGenericCall.

    @param[in]      Argument - Unused.

    @result         0.
 */
_Use_decl_annotations_
static
ULONG_PTR
SvpTlbFlushIpiRoutine (
    ULONG_PTR Argument
    )
{
    UNREFERENCED_PARAMETER(Argument);
    SvIssueVmmcall(HVREQ_FLUSH_TLB);
    return 0;
}

/*!
    @brief          Flushes the nested TLB on every processor.

    @details        Required after mutating shared NPT entries so no core keeps a
                    stale (executable) translation for the trapped page.
 */
_IRQL_requires_max_(APC_LEVEL)
static
VOID
SvFlushNestedTlbAllProcessors (
    VOID
    )
{
    (VOID)KeIpiGenericCall(SvpTlbFlushIpiRoutine, 0);
}

/*!
    @brief          KeIpiGenericCall worker: enables the RDTSC/RDTSCP intercept
                    on the executing processor (via a VMMCALL).
 */
_Use_decl_annotations_
static
ULONG_PTR
SvpCloakOnIpiRoutine (
    ULONG_PTR Argument
    )
{
    UNREFERENCED_PARAMETER(Argument);
    SvIssueVmmcall(HVREQ_CLOAK_ON);
    return 0;
}

/*!
    @brief          KeIpiGenericCall worker: disables the RDTSC/RDTSCP intercept
                    on the executing processor (via a VMMCALL).
 */
_Use_decl_annotations_
static
ULONG_PTR
SvpCloakOffIpiRoutine (
    ULONG_PTR Argument
    )
{
    UNREFERENCED_PARAMETER(Argument);
    SvIssueVmmcall(HVREQ_CLOAK_OFF);
    return 0;
}

/*!
    @brief          Enables TSC cloaking: installs the RDTSC/RDTSCP intercept on
                    every processor. Guest RDTSC/RDTSCP then #VMEXIT and are
                    emulated (CR3-gated correction) by SvHandleRdtsc.
 */
_IRQL_requires_max_(APC_LEVEL)
static
VOID
SvEnableTscCloakAllProcessors (
    VOID
    )
{
    (VOID)KeIpiGenericCall(SvpCloakOnIpiRoutine, 0);
}

/*!
    @brief          Disables TSC cloaking: removes the RDTSC/RDTSCP intercept on
                    every processor (guest RDTSC/RDTSCP run natively again).
 */
_IRQL_requires_max_(APC_LEVEL)
static
VOID
SvDisableTscCloakAllProcessors (
    VOID
    )
{
    (VOID)KeIpiGenericCall(SvpCloakOffIpiRoutine, 0);
}

/*!
    @brief          Tears down an active TSC cloak (intercept + gating), if any.

    @details        Idempotent. Called by the CLOAK_OFF IOCTL and at driver
                    teardown so the RDTSC intercept never outlives the driver.
 */
_IRQL_requires_max_(APC_LEVEL)
static
VOID
SvStopTscCloak (
    VOID
    )
{
    if (InterlockedCompareExchange(&g_Target.CloakActive, 0, 1) == 1)
    {
        SvDisableTscCloakAllProcessors();
        InterlockedExchange64(&g_Target.StolenTsc, 0);
        InterlockedExchange64(&g_Target.ParkTsc, 0);
        SvDebugPrint("TSC cloak OFF\n");
    }
}

/*!
    @brief          Handles #VMEXIT due to RDTSC / RDTSCP while cloaking.

    @details        Only reached when the RDTSC/RDTSCP intercept is installed
                    (cloak active). For the target process (CR3-gated) the
                    returned timestamp is reduced by StolenTsc so a freeze's
                    wall-clock gap is invisible; every other process reads the
                    true TSC. RDTSCP additionally returns IA32_TSC_AUX in ECX.

    @param[in,out]  VpData       - Per processor data.
    @param[in,out]  GuestContext - Guest's GPRs.
    @param[in]      IsRdtscp     - TRUE for RDTSCP (also set ECX = TSC_AUX).
 */
_IRQL_requires_same_
static
VOID
SvHandleRdtsc (
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext,
    _In_ BOOLEAN IsRdtscp
    )
{
    UINT64 tsc;
    UINT64 guestCr3;

    tsc = __rdtsc();

    if (InterlockedCompareExchange(&g_Target.CloakActive, 1, 1) != 0)
    {
        guestCr3 = VpData->GuestVmcb.StateSaveArea.Cr3;
        if ((guestCr3 & ~0xFFFULL) == (g_Target.TargetCr3 & ~0xFFFULL))
        {
            tsc -= static_cast<UINT64>(g_Target.StolenTsc);
        }
    }

    GuestContext->VpRegs->Rax = tsc & MAXUINT32;             // EAX = low 32 (RAX zero-extended)
    GuestContext->VpRegs->Rdx = (tsc >> 32) & MAXUINT32;     // EDX = high 32
    if (IsRdtscp != FALSE)
    {
        GuestContext->VpRegs->Rcx = __readmsr(IA32_MSR_TSC_AUX) & MAXUINT32;
    }

    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
}

/*!
    @brief          Fills a fresh 4KB split table for a 2MB NPT region.

    @details        Handles BOTH shapes of the current PDE: a 2MB large
                    page (identity base = PFN << 9) and an ALREADY-SPLIT
                    table pointer (the existing 512 leaves are copied, so
                    a re-split after a RECHECK move keeps every leaf; only
                    the target leaf is re-NXed). Returns FALSE when the PDE
                    is neither (invalid region state).
*/
static
BOOLEAN
SvFillSplitTableFromPde (
    _In_ PPD_ENTRY_2MB Pde,
    _Out_ PNESTED_PAGE_TABLE SplitTable
    )
{
    //
    // Review-2 fix (1): fill ONLY from a 2MB large-page PDE. An already-split
    // PDE is refused: reading a table pointer through the 2MB view names the
    // wrong frame, and copying a live split table would carry the OLD NX
    // leaf into the new table (the #NPF handler no longer knows that GPA —
    // an old-frame fetch would bugcheck). Same-region RECHECK moves pass
    // g_Target.SavedPde (the ORIGINAL large-page PDE) instead.
    //
    if (Pde->Fields.Valid == 0 || Pde->Fields.LargePage == 0)
    {
        return FALSE;
    }
    const UINT64 base4kFrame = static_cast<UINT64>(Pde->Fields.PageFrameNumber) << 9;
    for (ULONG i = 0; i < 512; i++)
    {
        SplitTable->Entries[i].AsUInt64 = 0;
        SplitTable->Entries[i].Fields.Valid = 1;
        SplitTable->Entries[i].Fields.Write = 1;
        SplitTable->Entries[i].Fields.User = 1;
        SplitTable->Entries[i].Fields.PageFrameNumber = base4kFrame + i;
        SplitTable->Entries[i].Fields.NoExecute = 0;
    }
    return TRUE;
}

/*!
    @brief          Installs the NPT execute-trap for the target page.

    @details        Resolves the target's guest-physical page (by attaching to
                    the process and calling MmGetPhysicalAddress), pins it with an
                    MDL, splits the covering 2MB PDE into 512 4KB PTEs, and marks
                    the single target leaf No-Execute. Runs at PASSIVE_LEVEL from
                    the ARM IOCTL.

    @param[in]      Pid - Target process id.
    @param[in]      TargetRip - Absolute guest-virtual address to trap on.
    @param[in]      ParkStubVa - VA of the "jmp $" stub in the target.

    @result         STATUS_SUCCESS or an error code.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
static
NTSTATUS
SvArmNptTrap (
    _In_ UINT64 Pid,
    _In_ UINT64 TargetRip,
    _In_ UINT64 ParkStubVa,
    _In_ const HVSNAP_PREDICATE* Predicate,
    _In_ UINT64 HitSkip,
    _In_ BOOLEAN CloakTsc
    )
{
    NTSTATUS status;
    PEPROCESS process;
    KAPC_STATE apcState;
    BOOLEAN attached;
    BOOLEAN locked;
    PMDL mdl;
    PNESTED_PAGE_TABLE splitTable;
    PVOID pageVa;
    PHYSICAL_ADDRESS pa;
    PHYSICAL_ADDRESS ptPa;
    UINT64 cr3;
    UINT64 gpa;
    ULONG pml4Index, pdptIndex, pdIndex, ptIndex;
    PPML4E_TREE tree;
    PPD_ENTRY_2MB pde;
    PPML4_ENTRY_2MB pdeAsTablePointer;

    process = nullptr;
    attached = FALSE;
    locked = FALSE;
    mdl = nullptr;
    splitTable = nullptr;
    cr3 = 0;
    pa.QuadPart = 0;

    if (g_SharedVpData == nullptr)
    {
        return STATUS_DEVICE_NOT_READY;
    }
    if (InterlockedCompareExchange(&g_Target.NptArmed, 1, 1) != 0)
    {
        return STATUS_DEVICE_BUSY;
    }

    status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(Pid), &process);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    pageVa = reinterpret_cast<PVOID>(TargetRip & ~(static_cast<UINT64>(PAGE_SIZE) - 1));

    //
    // Attach to the target to read its CR3 and translate/pin the target page.
    //
    KeStackAttachProcess(process, &apcState);
    attached = TRUE;
    __try
    {
        cr3 = __readcr3();
        mdl = IoAllocateMdl(pageVa, PAGE_SIZE, FALSE, FALSE, nullptr);
        if (mdl == nullptr)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }
        MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
        locked = TRUE;
        pa = MmGetPhysicalAddress(reinterpret_cast<PVOID>(TargetRip));
        if (pa.QuadPart == 0)
        {
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }
        //
        // Review fix (4): derive gpa from the LOCKED MDL's frame, not a
        // second lookup — a COW between the lock and this read would
        // otherwise trap a frame that is not the pinned one.
        //
        pa.QuadPart = static_cast<LONGLONG>(
            MmGetMdlPfnArray(mdl)[0]) << PAGE_SHIFT;
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apcState);
    attached = FALSE;

    if (!NT_SUCCESS(status))
    {
        goto Failure;
    }

    gpa = static_cast<UINT64>(pa.QuadPart) & ~(static_cast<UINT64>(PAGE_SIZE) - 1);

    //
    // The identity map only covers the first 1 TB (two PML4 entries).
    //
    pml4Index = static_cast<ULONG>((gpa >> 39) & 0x1FF);
    if (pml4Index >= 2)
    {
        status = STATUS_NOT_SUPPORTED;
        goto Failure;
    }
    pdptIndex = static_cast<ULONG>((gpa >> 30) & 0x1FF);
    pdIndex = static_cast<ULONG>((gpa >> 21) & 0x1FF);
    ptIndex = static_cast<ULONG>((gpa >> 12) & 0x1FF);

    //
    // Allocate the 4KB page table that replaces the 2MB large page.
    //
    splitTable = static_cast<PNESTED_PAGE_TABLE>(
        SvAllocatePageAlingedPhysicalMemory(sizeof(NESTED_PAGE_TABLE)));
    if (splitTable == nullptr)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Failure;
    }

    tree = &g_SharedVpData->Pml4eTrees[pml4Index];
    pde = &tree->PdEntries[pdptIndex][pdIndex];

    //
    // Fill 512 identity leaf PTEs for the 2MB region (large page or an
    // already-split table), then arm the target leaf.
    //
    if (SvFillSplitTableFromPde(pde, splitTable) == FALSE)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Failure;
    }
    splitTable->Entries[ptIndex].Fields.NoExecute = 1;

    //
    // Publish the session state BEFORE installing the trap. Once the PDE is
    // repointed (below) a #NPF can occur on any core; the handler must already
    // see NptArmed == 1 and a fully populated g_Target (split table, indices,
    // gate values), otherwise it would treat the fault as unexpected and crash.
    //
    g_Target.SavedPde = *pde;
    g_Target.TargetPid = Pid;
    g_Target.TargetRip = TargetRip;
    g_Target.ParkStubVa = ParkStubVa;
    g_Target.TargetCr3 = cr3;
    g_Target.TargetGpa = gpa;
    g_Target.PtIndex = ptIndex;
    g_Target.Pde = pde;
    g_Target.SplitTable = splitTable;
    g_Target.LockedMdl = mdl;
    g_Target.TargetProcess = process;
    g_Target.Predicate = *Predicate;
    g_Target.HitSkip = HitSkip;
    InterlockedExchange(&g_Target.Hit, 0);
    InterlockedExchange(&g_Target.HitReady, 0);
    g_Target.HitTid = 0;
    g_Target.HitFsBase = 0;
    g_Target.HitGsBase = 0;
    g_Target.HitCr0 = 0;
    g_Target.HitCr2 = 0;
    g_Target.HitCr3 = 0;
    g_Target.HitCr4 = 0;
    g_Target.HitEfer = 0;
    g_Target.HitDr6 = 0;
    g_Target.HitDr7 = 0;
    g_Target.HitStar = 0;
    g_Target.HitLStar = 0;
    g_Target.HitCStar = 0;
    g_Target.HitSfMask = 0;
    g_Target.HitKernelGsBase = 0;
    g_Target.HitSysenterCs = 0;
    g_Target.HitSysenterEsp = 0;
    g_Target.HitSysenterEip = 0;
    g_Target.HitCpl = 0;
    g_Target.HitGPat = 0;
    g_Target.HitDbgCtl = 0;
    g_Target.HitTscGuest = 0;
    g_Target.HitTscAux = 0;
    g_Target.HitCr8 = 0;
    g_Target.HitGdtrBase = 0;
    g_Target.HitIdtrBase = 0;
    g_Target.HitLdtrBase = 0;
    g_Target.HitTrBase = 0;
    g_Target.HitGdtrLimit = 0;
    g_Target.HitIdtrLimit = 0;
    g_Target.HitLdtrLimit = 0;
    g_Target.HitTrLimit = 0;
    g_Target.HitLdtrAttrib = 0;
    g_Target.HitTrAttrib = 0;
    g_Target.HitLdtrSelector = 0;
    g_Target.HitTrSelector = 0;
    InterlockedExchange64(&g_Target.ParkedCount, 0);
    InterlockedExchange64(&g_Target.MatchCount, 0);
    KeMemoryBarrier();
    InterlockedExchange(&g_Target.NptArmed, 1);
    InterlockedExchange(&g_Target.Active, 1);

    //
    // Install the trap: repoint the PDE at the new 4KB page table (clear the
    // large-page bit) using the 4KB-entry view (PageFrameNumber [12:51]) to
    // write a table pointer. From here, fetches of the target page fault.
    // Build the entry in a local and publish it with ONE 64-bit store so a
    // concurrent walk on another core never sees a not-present or
    // frame-0 PDE.
    //
    ptPa = MmGetPhysicalAddress(splitTable);
    {
        PML4_ENTRY_2MB pdeValue;
        pdeValue.AsUInt64 = 0;
        pdeValue.Fields.Valid = 1;
        pdeValue.Fields.Write = 1;
        pdeValue.Fields.User = 1;
        pdeValue.Fields.PageFrameNumber =
            static_cast<UINT64>(ptPa.QuadPart) >> PAGE_SHIFT;
        pdeValue.Fields.NoExecute = 0;
        pdeAsTablePointer = reinterpret_cast<PPML4_ENTRY_2MB>(pde);
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&pdeAsTablePointer->AsUInt64),
                              static_cast<LONG64>(pdeValue.AsUInt64));
    }

    //
    // Flush every core's nested TLB so the split/NX takes effect everywhere.
    //
    SvFlushNestedTlbAllProcessors();

    //
    // TSC cloak (feature #2): if requested and not already active, install the
    // RDTSC/RDTSCP intercept on every core. TargetCr3 (published above) gates
    // the correction. StolenTsc starts at 0; DISARM folds each freeze's gap in.
    //
    if (CloakTsc != FALSE &&
        InterlockedCompareExchange(&g_Target.CloakActive, 1, 0) == 0)
    {
        InterlockedExchange64(&g_Target.StolenTsc, 0);
        InterlockedExchange64(&g_Target.ParkTsc, 0);
        SvEnableTscCloakAllProcessors();
        SvDebugPrint("TSC cloak ON: cr3=0x%llx\n", cr3);
    }

    SvDebugPrint("ARM NPT: pid=%llu rip=0x%llx gpa=0x%llx cr3=0x%llx parkStub=0x%llx\n",
                 Pid, TargetRip, gpa, cr3, ParkStubVa);
    return STATUS_SUCCESS;

Failure:
    if (attached != FALSE)
    {
        KeUnstackDetachProcess(&apcState);
    }
    if (splitTable != nullptr)
    {
        SvFreePageAlingedPhysicalMemory(splitTable);
    }
    if (locked != FALSE)
    {
        MmUnlockPages(mdl);
    }
    if (mdl != nullptr)
    {
        IoFreeMdl(mdl);
    }
    if (process != nullptr)
    {
        ObDereferenceObject(process);
    }
    return status;
}

/*!
    @brief          Removes the NPT execute-trap and frees its resources.

    @details        Restores the original 2MB large-page PDE, flushes the nested
                    TLB on all cores, frees the split table, unlocks/pins, and
                    dereferences the target process. Runs at PASSIVE_LEVEL.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
static
VOID
SvDisarmNptTrap (
    VOID
    )
{
    InterlockedExchange(&g_Target.Active, 0);

    //
    // TSC cloak (feature #2): the target is about to be resumed. Fold the
    // freeze's wall-clock duration (park -> now) into StolenTsc so the target's
    // post-resume RDTSC/RDTSCP reads are reduced by it and the gap is invisible.
    // Cloaking itself stays active (intercept remains) for the target's life.
    // Clear ParkTsc so a redundant DISARM cannot double-count.
    //
    if (InterlockedCompareExchange(&g_Target.CloakActive, 1, 1) != 0)
    {
        LONG64 parkTsc = InterlockedExchange64(&g_Target.ParkTsc, 0);
        if (parkTsc != 0)
        {
            LONG64 delta = static_cast<LONG64>(__rdtsc()) - parkTsc;
            if (delta > 0)
            {
                InterlockedExchangeAdd64(&g_Target.StolenTsc, delta);
                SvDebugPrint("TSC cloak: hid %lld cycles (total %lld)\n",
                             delta, g_Target.StolenTsc);
            }
        }
    }

    //
    // Non-destructive check: is a trap installed? (Compare 1,1 leaves it as-is.)
    // Leave NptArmed == 1 across the PDE restore + flush so any in-flight #NPF /
    // #DB (step-over) handler still sees a valid, armed g_Target rather than
    // taking the "unexpected fault" crash path.
    //
    if (InterlockedCompareExchange(&g_Target.NptArmed, 1, 1) == 0)
    {
        //
        // Was not armed.
        //
        return;
    }

    //
    // Restore the original 2MB large-page mapping (page executable again), then
    // flush every core. The flush synchronizes all processors through a
    // VMEXIT/VMRUN, so any handler that was mid step-over completes (and stops
    // touching the split table) before we free it. Only after that do we clear
    // NptArmed and release resources.
    //
    if (g_Target.Pde != nullptr)
    {
        *g_Target.Pde = g_Target.SavedPde;
    }
    SvFlushNestedTlbAllProcessors();

    InterlockedExchange(&g_Target.NptArmed, 0);

    if (g_Target.SplitTable != nullptr)
    {
        SvFreePageAlingedPhysicalMemory(g_Target.SplitTable);
        g_Target.SplitTable = nullptr;
    }
    if (g_Target.LockedMdl != nullptr)
    {
        MmUnlockPages(g_Target.LockedMdl);
        IoFreeMdl(g_Target.LockedMdl);
        g_Target.LockedMdl = nullptr;
    }
    if (g_Target.TargetProcess != nullptr)
    {
        ObDereferenceObject(g_Target.TargetProcess);
        g_Target.TargetProcess = nullptr;
    }
    g_Target.Pde = nullptr;

    SvDebugPrint("DISARM NPT\n");
}

/*!
    @brief          Re-resolves the trapped VA and MOVES the NPT execute-trap.

    @details        Stage A of the VA-trap fix (Z, 2026-11-25): an ARM-time
                    translation goes stale when the loader copy-on-writes the
                    RWX image page (in-place unpacking/decryption), leaving the
                    NX leaf guarding a frame nobody executes. RECHECK resolves
                    the target VA again; when the backing guest-physical frame
                    changed it MOVES the trap — never repoints a live leaf's
                    PFN (that would alias every old-GPA access onto the new
                    frame). Review-hardened order (F's kernel-safety review):

                    1. Pin the new frame under attach (locked flag; the MDL's
                       PFN is the trapped frame — no second lookup; probe
                       failures abort with the OLD trap still armed and the
                       error returned).
                    2. Validate the >1 TB identity-map limit; allocate AND
                       fill the new split table BEFORE any teardown, so
                       g_Target.SplitTable is never null while NptArmed is 1,
                       and any failure here leaves the old trap fully armed.
                    3. Swap in ONE window: capture the old region/PDE/MDL
                       locals, publish the new table/index/gpa/MDL into
                       g_Target, repoint the new region's PDE with a single
                       64-bit store, restore the old region's PDE (single
                       store) when the move crossed regions, flush every core,
                       and only then free the old split table and unlock the
                       old MDL — the flush retires any in-flight #NPF/#DB
                       handler before the old resources go away.

                    NptArmed stays 1 across the move. No-op success
                    (Changed=0) when the frame is unchanged, the trap is not
                    armed, or the target already parked; errors propagate
                    (hvctl surfaces them). Serialized by a busy flag.

    @param[out]     Reply - old/new GPAs and Changed (always filled).

    @result         STATUS_SUCCESS (see Changed), or an error.
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
static
NTSTATUS
SvRecheckNptTrap (
    _Out_ PHVSNAP_RECHECK_REPLY Reply
    )
{
    NTSTATUS status;
    KAPC_STATE apcState;
    BOOLEAN attached;
    BOOLEAN newLocked;
    PMDL newMdl;
    PMDL oldMdl;
    PNESTED_PAGE_TABLE newSplit;
    PNESTED_PAGE_TABLE oldSplit;
    PD_ENTRY_2MB oldSavedPde;
    PPD_ENTRY_2MB oldPde;
    UINT64 newGpa;
    UINT64 cr3;
    ULONG pml4Index, pdptIndex, pdIndex, ptIndex;
    PPML4E_TREE tree;
    PPD_ENTRY_2MB newPde;
    PPML4_ENTRY_2MB newPdeAsTablePointer;
    PML4_ENTRY_2MB newPdeValue;
    PHYSICAL_ADDRESS ptPa;
    BOOLEAN sameRegion;
    PD_ENTRY_2MB newRegionOriginal;

    RtlZeroMemory(Reply, sizeof(*Reply));
    Reply->OldGpa = g_Target.TargetGpa;

    if (g_SharedVpData == nullptr)
    {
        return STATUS_DEVICE_NOT_READY;
    }
    if (InterlockedCompareExchange(&g_Target.NptArmed, 1, 1) == 0)
    {
        return STATUS_SUCCESS;              // not armed: nothing to re-resolve
    }
    if (InterlockedCompareExchange(&g_Target.Hit, 1, 1) != 0)
    {
        return STATUS_SUCCESS;              // already parked: leave it alone
    }
    if (InterlockedCompareExchange(&g_RecheckBusy, 1, 0) != 0)
    {
        return STATUS_DEVICE_BUSY;
    }

    attached = FALSE;
    newLocked = FALSE;
    newMdl = nullptr;
    newSplit = nullptr;
    newGpa = 0;
    cr3 = 0;
    newRegionOriginal.AsUInt64 = 0;

    //
    // (1) Resolve and PIN the new frame first. The MDL's PFN is the trapped
    // frame (review fix 4): a COW between lock and a second lookup would
    // otherwise trap an unpinned frame. A probe failure aborts with the old
    // trap still armed and returns the ERROR (review fix 1: unlock only the
    // locked, always free the MDL, never swallow the error).
    //
    KeStackAttachProcess(g_Target.TargetProcess, &apcState);
    attached = TRUE;
    __try
    {
        cr3 = __readcr3();
        newMdl = IoAllocateMdl(reinterpret_cast<PVOID>(g_Target.TargetRip & ~(static_cast<UINT64>(PAGE_SIZE) - 1)),
                               PAGE_SIZE, FALSE, FALSE, nullptr);
        if (newMdl == nullptr)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }
        MmProbeAndLockPages(newMdl, UserMode, IoReadAccess);
        newLocked = TRUE;
        newGpa = static_cast<UINT64>(
            MmGetMdlPfnArray(newMdl)[0]) << PAGE_SHIFT;
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apcState);
    attached = FALSE;

    if (!NT_SUCCESS(status))
    {
        goto Abort;                          // old trap still armed; return error
    }

    if (newGpa == g_Target.TargetGpa)
    {
        Reply->NewGpa = newGpa;
        goto Abort;                          // unchanged: release the new pin
    }

    //
    // A park may have raced in while we resolved; re-check before moving.
    //
    if (InterlockedCompareExchange(&g_Target.Hit, 1, 1) != 0)
    {
        Reply->NewGpa = newGpa;
        goto Abort;
    }

    //
    // (2) Validate + allocate + fill the new split table BEFORE any teardown
    // (review fixes 2 and 3): g_Target.SplitTable never becomes null while
    // NptArmed is 1, and a failure here leaves the old trap fully armed.
    //
    pml4Index = static_cast<ULONG>((newGpa >> 39) & 0x1FF);
    if (pml4Index >= 2)
    {
        status = STATUS_NOT_SUPPORTED;
        goto Abort;                          // old trap still armed
    }
    pdptIndex = static_cast<ULONG>((newGpa >> 30) & 0x1FF);
    pdIndex = static_cast<ULONG>((newGpa >> 21) & 0x1FF);
    ptIndex = static_cast<ULONG>((newGpa >> 12) & 0x1FF);

    newSplit = static_cast<PNESTED_PAGE_TABLE>(
        SvAllocatePageAlingedPhysicalMemory(sizeof(NESTED_PAGE_TABLE)));
    if (newSplit == nullptr)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Abort;                          // old trap still armed
    }

    tree = &g_SharedVpData->Pml4eTrees[pml4Index];
    newPde = &tree->PdEntries[pdptIndex][pdIndex];
    sameRegion = (newPde == g_Target.Pde);
    //
    // Review-2 fix (1): a same-region move must fill from the ORIGINAL
    // large-page PDE (g_Target.SavedPde) — the live PDE is our split
    // pointer, which SvFillSplitTableFromPde now refuses. A cross-region
    // move fills from the new region's untouched PDE (captured now, before
    // any restore touches anything).
    //
    if (SvFillSplitTableFromPde(sameRegion ? &g_Target.SavedPde : newPde,
                                newSplit) == FALSE)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Abort;                          // old trap still armed
    }
    newSplit->Entries[ptIndex].Fields.NoExecute = 1;
    if (!sameRegion)
    {
        newRegionOriginal = *newPde;         // the new region's original PDE
    }

    ptPa = MmGetPhysicalAddress(newSplit);
    newPdeValue.AsUInt64 = 0;
    newPdeValue.Fields.Valid = 1;
    newPdeValue.Fields.Write = 1;
    newPdeValue.Fields.User = 1;
    newPdeValue.Fields.PageFrameNumber =
        static_cast<UINT64>(ptPa.QuadPart) >> PAGE_SHIFT;
    newPdeValue.Fields.NoExecute = 0;

    //
    // (3) The swap — review-2 fix (2): retire the OLD leaf first (restore
    // + flush), THEN publish the new state and repoint. While the old NX
    // leaf is live, g_Target still describes it, so an old-frame fetch on
    // another core matches TargetGpa and parks normally (no :1095
    // bugcheck); after the restore+flush the old leaf is gone and the
    // handler cannot see half-published state.
    //
    oldPde = g_Target.Pde;
    oldSavedPde = g_Target.SavedPde;         // the old region's original PDE
    oldSplit = g_Target.SplitTable;
    oldMdl = g_Target.LockedMdl;

    if (!sameRegion && oldPde != nullptr)
    {
        //
        // Cross-region: restore the old region's ORIGINAL PDE (single
        // store, exactly what disarm does) and flush — the old leaf dies
        // here, before any state moves.
        //
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&oldPde->AsUInt64),
                              static_cast<LONG64>(oldSavedPde.AsUInt64));
        SvFlushNestedTlbAllProcessors();
    }
    else if (sameRegion)
    {
        //
        // Same region: restore the ORIGINAL large page (killing the old
        // split + NX leaf), flush, then repoint at the new table below.
        //
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&oldPde->AsUInt64),
                              static_cast<LONG64>(oldSavedPde.AsUInt64));
        SvFlushNestedTlbAllProcessors();
    }

    //
    // Publish the new state (the ARM ordering rule: a #NPF on the new leaf
    // must find a consistent g_Target), then repoint with a single store.
    //
    g_Target.TargetGpa = newGpa;
    g_Target.PtIndex = ptIndex;
    g_Target.Pde = newPde;
    g_Target.SplitTable = newSplit;
    g_Target.LockedMdl = newMdl;
    if (!sameRegion)
    {
        g_Target.SavedPde = newRegionOriginal; // captured before the restore
    }
    // sameRegion keeps the existing SavedPde (the original large-page PDE).
    g_Target.TargetCr3 = cr3;
    newMdl = nullptr;                          // ownership moved to g_Target
    KeMemoryBarrier();

    newPdeAsTablePointer = reinterpret_cast<PPML4_ENTRY_2MB>(newPde);
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&newPdeAsTablePointer->AsUInt64),
                          static_cast<LONG64>(newPdeValue.AsUInt64));
    SvFlushNestedTlbAllProcessors();

    //
    // The flush has retired every in-flight handler; free the old resources.
    //
    if (oldSplit != nullptr)
    {
        SvFreePageAlingedPhysicalMemory(oldSplit);
    }
    if (oldMdl != nullptr)
    {
        MmUnlockPages(oldMdl);
        IoFreeMdl(oldMdl);
    }

    Reply->NewGpa = newGpa;
    Reply->Changed = 1;

    SvDebugPrint("RECHECK NPT: MOVED rip=0x%llx oldGpa=0x%llx newGpa=0x%llx cr3=0x%llx\n",
                 g_Target.TargetRip, Reply->OldGpa, newGpa, cr3);
    InterlockedExchange(&g_RecheckBusy, 0);
    return STATUS_SUCCESS;

Abort:
    //
    // Not moved: release the new pin (only if locked), free any new split,
    // and return the STATUS (review fix 1).
    //
    if (newMdl != nullptr)
    {
        if (newLocked != FALSE)
        {
            MmUnlockPages(newMdl);
        }
        IoFreeMdl(newMdl);
    }
    if (newSplit != nullptr)
    {
        SvFreePageAlingedPhysicalMemory(newSplit);
    }
    InterlockedExchange(&g_RecheckBusy, 0);
    return status;
}


/*!
    @brief          Allocates the register-trace ring and enables capture.

    @param[in]      RingBytes - requested ring size in bytes (floored/rounded).

    @result         STATUS_SUCCESS, or an error if already tracing / OOM.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
static
NTSTATUS
SvTraceStart (
    _In_ UINT64 RingBytes
    )
{
    SIZE_T bytes;
    const SIZE_T floorBytes = sizeof(HVSNAP_RECORD) * 4096;    // >= 4096 slots

    if (g_Trace.Ring != nullptr)
    {
        return STATUS_DEVICE_BUSY;                              // stop the previous trace first
    }

    bytes = (RingBytes < floorBytes) ? floorBytes : static_cast<SIZE_T>(RingBytes);

    g_Trace.Ring = static_cast<PHVSNAP_RECORD>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, HVSNAP_TRACE_POOL_TAG));
    if (g_Trace.Ring == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_Trace.RingBytes = bytes;
    g_Trace.Capacity = bytes / sizeof(HVSNAP_RECORD);
    InterlockedExchange64(&g_Trace.WriteIndex, 0);
    g_Trace.ReadIndex = 0;
    InterlockedExchange64(&g_Trace.DropCount, 0);
    KeMemoryBarrier();
    InterlockedExchange(&g_Trace.Enabled, 1);
    SvDebugPrint("TRACE START: ring=%llu bytes, %llu slots\n",
                 static_cast<UINT64>(bytes), g_Trace.Capacity);
    return STATUS_SUCCESS;
}

/*!
    @brief          Disables capture and frees the trace ring.

    @details        Callers MUST have disarmed the NPT trap first (SvDisarmNptTrap
                    synchronizes all cores through a VMEXIT, so no core is mid
                    SvTraceCapture). A best-effort cross-core sync is issued here
                    too. Idempotent.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
static
VOID
SvTraceStop (
    VOID
    )
{
    if (InterlockedCompareExchange(&g_Trace.Enabled, 0, 1) == 1)
    {
        SvFlushNestedTlbAllProcessors();       // round-trip every core; belt & suspenders
    }
    if (g_Trace.Ring != nullptr)
    {
        ExFreePoolWithTag(g_Trace.Ring, HVSNAP_TRACE_POOL_TAG);
        g_Trace.Ring = nullptr;
        g_Trace.Capacity = 0;
        g_Trace.RingBytes = 0;
        SvDebugPrint("TRACE STOP\n");
    }
}

/*!
    @brief          Copies newly-captured records into the caller's output buffer.

    @details        Fills an HVSNAP_DRAIN_HEADER then as many complete records as
                    fit. On ring overrun (producer lapped the consumer) it resyncs
                    to the oldest still-present record and accounts the loss. Runs
                    at PASSIVE from the TRACE_DRAIN IOCTL (OutBuf is the buffered
                    system copy).

    @result         STATUS_SUCCESS (or STATUS_BUFFER_TOO_SMALL).
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
static
NTSTATUS
SvTraceDrain (
    _Out_writes_bytes_(OutLen) PVOID OutBuf,
    _In_ ULONG OutLen,
    _Out_ PULONG_PTR Information
    )
{
    PHVSNAP_DRAIN_HEADER hdr;
    PHVSNAP_RECORD out;
    LONG64 w;
    LONG64 r;
    ULONG maxRecs;
    ULONG n;

    *Information = 0;
    if (OutLen < sizeof(HVSNAP_DRAIN_HEADER))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    hdr = static_cast<PHVSNAP_DRAIN_HEADER>(OutBuf);
    RtlZeroMemory(hdr, sizeof(*hdr));
    hdr->RecordSize = sizeof(HVSNAP_RECORD);

    if (g_Trace.Ring == nullptr || g_Trace.Capacity == 0)
    {
        *Information = sizeof(*hdr);
        return STATUS_SUCCESS;
    }

    w = g_Trace.WriteIndex;
    r = g_Trace.ReadIndex;

    //
    // Overrun: the producer wrote more than Capacity ahead of us. The oldest
    // still-present record is (w - Capacity); everything before it is gone.
    //
    if (w - r > static_cast<LONG64>(g_Trace.Capacity))
    {
        LONG64 oldest = w - static_cast<LONG64>(g_Trace.Capacity);
        InterlockedExchangeAdd64(&g_Trace.DropCount, oldest - r);
        r = oldest;
    }

    out = reinterpret_cast<PHVSNAP_RECORD>(static_cast<PUCHAR>(OutBuf) + sizeof(HVSNAP_DRAIN_HEADER));
    maxRecs = (OutLen - sizeof(HVSNAP_DRAIN_HEADER)) / sizeof(HVSNAP_RECORD);

    n = 0;
    while (r < w && n < maxRecs)
    {
        PHVSNAP_RECORD src = &g_Trace.Ring[static_cast<UINT64>(r) % g_Trace.Capacity];
        if (src->HitIndex != static_cast<UINT64>(r))
        {
            //
            // Slot not yet published (producer mid-write) or already overwritten;
            // stop here and pick it up on the next drain.
            //
            break;
        }
        RtlCopyMemory(&out[n], src, sizeof(HVSNAP_RECORD));
        n++;
        r++;
    }

    g_Trace.ReadIndex = r;
    hdr->RecordCount = n;
    hdr->TotalWritten = static_cast<UINT64>(w);
    hdr->TotalDropped = static_cast<UINT64>(g_Trace.DropCount);
    hdr->MoreAvailable = (r < g_Trace.WriteIndex) ? 1 : 0;
    *Information = sizeof(HVSNAP_DRAIN_HEADER) + n * sizeof(HVSNAP_RECORD);
    return STATUS_SUCCESS;
}

/*!
    @brief          Injects an #UD (invalid opcode, vector 6) into the guest.

    @details        Used to make a VMMCALL from user mode / with no pending
                    request look exactly like an unsupported instruction on bare
                    metal, so it cannot be used to detect the hypervisor. Does not
                    advance RIP (the fault is reported at the faulting instruction).
 */
_IRQL_requires_same_
static
VOID
SvInjectUdException (
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
    )
{
    EVENTINJ event;

    event.AsUInt64 = 0;
    event.Fields.Vector = 6;    // #UD
    event.Fields.Type = 3;      // exception
    event.Fields.Valid = 1;
    VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}

/*!
    @brief          Handles #VMEXIT due to VMMCALL (the guest->host control bridge).

    @details        CPUID is passed through natively for stealth; internal control
                    signals (nested-TLB flush, TSC-cloak on/off, unload) come in as
                    a VMMCALL with the request kind in this CPU's g_VmmcallReq slot.
                    Only a ring-0 VMMCALL with a pending request is honored; any
                    other VMMCALL (user mode, or a probe with no request) is
                    reflected as #UD so it looks unsupported.

    @param[in,out]  VpData - Per processor data.
    @param[in,out]  GuestContext - Guest's GPRs.
 */
_IRQL_requires_same_
static
VOID
SvHandleVmmcall (
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
    )
{
    SEGMENT_ATTRIBUTE attribute;
    ULONG cpu;
    LONG req;

    attribute.AsUInt16 = VpData->GuestVmcb.StateSaveArea.SsAttrib;
    cpu = KeGetCurrentProcessorNumberEx(nullptr);
    req = (cpu < HVSNAP_MAX_PROCESSORS) ? g_VmmcallReq[cpu] : HVREQ_NONE;

    if ((attribute.Fields.Dpl != DPL_SYSTEM) || (req == HVREQ_NONE))
    {
        //
        // Not one of ours (user mode, or a probe with no pending request). Make
        // VMMCALL appear unsupported. Do NOT advance RIP.
        //
        SvInjectUdException(VpData);
        return;
    }

    //
    // Consume the request so a stray VMMCALL cannot replay it.
    //
    g_VmmcallReq[cpu] = HVREQ_NONE;

    switch (req)
    {
    case HVREQ_FLUSH_TLB:
        VpData->GuestVmcb.ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_ALL;
        break;
    case HVREQ_CLOAK_ON:
        VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_RDTSC;
        VpData->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_RDTSCP;
        VpData->GuestVmcb.ControlArea.VmcbClean = 0;
        break;
    case HVREQ_CLOAK_OFF:
        VpData->GuestVmcb.ControlArea.InterceptMisc1 &= ~SVM_INTERCEPT_MISC1_RDTSC;
        VpData->GuestVmcb.ControlArea.InterceptMisc2 &= ~SVM_INTERCEPT_MISC2_RDTSCP;
        VpData->GuestVmcb.ControlArea.VmcbClean = 0;
        break;
    case HVREQ_UNLOAD:
        //
        // Request devirtualization of this processor. The ExitVm path (in
        // SvHandleVmExit) performs the hand-off back to SvVmmcall's next
        // instruction (using NRip), so do not advance RIP here.
        //
        GuestContext->ExitVm = TRUE;
        return;
    default:
        break;
    }

    //
    // Advance past the VMMCALL for the non-unload requests.
    //
    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
}

/*!
    @brief          Handles #VMEXIT due to execution of the WRMSR and RDMSR
                    instructions.

    @details        This protects EFER.SVME from being cleared by the guest by
                    injecting #GP when it is about to be cleared. For other MSR
                    access, it passes-through.

    @param[in,out]  VpData - Per processor data.
    @param[in,out]  GuestContext - Guest's GPRs.
 */
_IRQL_requires_same_
static
VOID
SvHandleMsrAccess (
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
    )
{
    ULARGE_INTEGER value;
    UINT32 msr;
    BOOLEAN writeAccess;

    msr = GuestContext->VpRegs->Rcx & MAXUINT32;
    writeAccess = (VpData->GuestVmcb.ControlArea.ExitInfo1 != 0);

    //
    // If IA32_MSR_EFER is accessed for write, we must protect the EFER_SVME bit
    // from being cleared.
    //
    if (msr == IA32_MSR_EFER)
    {
        //
        // #VMEXIT on IA32_MSR_EFER access should only occur on write access.
        //
        NT_ASSERT(writeAccess != FALSE);

        value.LowPart = GuestContext->VpRegs->Rax & MAXUINT32;
        value.HighPart = GuestContext->VpRegs->Rdx & MAXUINT32;
        if ((value.QuadPart & EFER_SVME) == 0)
        {
            //
            // Inject #GP if the guest attempts to clear the SVME bit. Protection of
            // this bit is required because clearing the bit while guest is running
            // leads to undefined behavior.
            //
            SvInjectGeneralProtectionException(VpData);
            return;
        }

        //
        // Otherwise, update the MSR as requested. Important to note that the value
        // should be checked not to allow any illegal values, and inject #GP as
        // needed. Otherwise, the hypervisor attempts to resume the guest with an
        // illegal EFER and immediately receives #VMEXIT due to VMEXIT_INVALID,
        // which in our case, results in a bug check. See "Extended Feature Enable
        // Register (EFER)" for what values are allowed.
        //
        // This code does not implement the check intentionally, for simplicity.
        //
        VpData->GuestVmcb.StateSaveArea.Efer = value.QuadPart;
    }
    else
    {
        //
        // If the MSR being accessed is not IA32_MSR_EFER, assert that #VMEXIT
        // can only occur on access to MSR outside the ranges controlled with
        // the MSR permissions map. This is true because the map is configured
        // not to intercept any MSR access but IA32_MSR_EFER. See
        // "MSR Ranges Covered by MSRPM" in "MSR Intercepts" for the MSR ranges
        // controlled by the map.
        //
        // Note that VMware Workstation has a bug that access to unimplemented
        // MSRs unconditionally causes #VMEXIT ignoring bits in the MSR
        // permissions map. This can be tested by reading MSR zero, for example.
        //
        NT_ASSERT(((msr > 0x00001fff) && (msr < 0xc0000000)) ||
                  ((msr > 0xc0001fff) && (msr < 0xc0010000)) ||
                   (msr > 0xc0011fff));

        //
        // Execute WRMSR or RDMSR on behalf of the guest. Important that this
        // can cause bug check when the guest tries to access unimplemented MSR
        // *even within the SEH block* because the below WRMSR or RDMSR raises
        // #GP and are not protected by the SEH block (or cannot be protected
        // either as this code run outside the thread stack region Windows
        // requires to proceed SEH). Hypervisors typically handle this by noop-ing
        // WRMSR and returning zero for RDMSR with non-architecturally defined
        // MSRs. Alternatively, one can probe which MSRs should cause #GP prior
        // to installation of a hypervisor and the hypervisor can emulate the
        // results.
        //
        if (writeAccess != FALSE)
        {
            value.LowPart = GuestContext->VpRegs->Rax & MAXUINT32;
            value.HighPart = GuestContext->VpRegs->Rdx & MAXUINT32;
            __writemsr(msr, value.QuadPart);
        }
        else
        {
            value.QuadPart = __readmsr(msr);
            GuestContext->VpRegs->Rax = value.LowPart;
            GuestContext->VpRegs->Rdx = value.HighPart;
        }
    }

    //
    // Then, advance RIP to "complete" the instruction.
    //
    VpData->GuestVmcb.StateSaveArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
}

/*!
    @brief          Handles #VMEXIT due to execution of the VMRUN instruction.

    @details        This function always injects #GP to the guest.

    @param[in,out]  VpData - Per processor data.
    @param[in,out]  GuestContext - Guest's GPRs.
 */
_IRQL_requires_same_
static
VOID
SvHandleVmrun (
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
    )
{
    UNREFERENCED_PARAMETER(GuestContext);

    SvInjectGeneralProtectionException(VpData);
}

/*!
    @brief          C-level entry point of the host code called from SvLaunchVm.

    @details        This function loads save host state first, and then, handles
                    #VMEXIT which may or may not change guest's state via VpData
                    or GuestRegisters.

                    Interrupts are disabled when this function is called due to
                    the cleared GIF. Not all host state are loaded yet, so do it
                    with the VMLOAD instruction.

                    If the #VMEXIT handler detects a request to unload the
                    hypervisor, this function loads guest state, disables SVM
                    and returns to execution flow where the #VMEXIT triggered.

    @param[in,out]  VpData - Per processor data.
    @param[in,out]  GuestRegisters - Guest's GPRs.

    @result         TRUE when virtualization is terminated; otherwise FALSE.
 */
_IRQL_requires_same_
EXTERN_C
BOOLEAN
NTAPI
SvHandleVmExit (
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_REGISTERS GuestRegisters
    )
{
    GUEST_CONTEXT guestContext;
    KIRQL oldIrql;

    guestContext.VpRegs = GuestRegisters;
    guestContext.ExitVm = FALSE;

    //
    // Load some host state that are not loaded on #VMEXIT.
    //
    __svm_vmload(VpData->HostStackLayout.HostVmcbPa);

    NT_ASSERT(VpData->HostStackLayout.Reserved1 == MAXUINT64);

    //
    // Latch the guest CR8 (TPR) BEFORE the IRQL raise below - KeRaiseIrql is
    // a mov-to-CR8 and would overwrite the guest's value. At #VMEXIT entry,
    // the physical CR8 register still holds the guest's TPR (nothing in the
    // exit path has touched it yet), so this is the same-hit guest value.
    // SvParkTargetThread copies it into the hit payload when this exit parks.
    //
    VpData->HostStackLayout.GuestCr8AtExit = __readcr8();

    //
    // Raise the IRQL to the DISPATCH_LEVEL level. This has no actual effect since
    // interrupts are disabled at #VMEXI but warrants bug check when some of
    // kernel API that are not usable on this context is called with Driver
    // Verifier. This protects developers from accidentally writing such #VMEXIT
    // handling code. This should actually raise IRQL to HIGH_LEVEL to represent
    // this running context better, but our Logger code is not designed to run at
    // that level unfortunately. Finally, note that this API is a thin wrapper
    // of mov-to-CR8 on x64 and safe to call on this context.
    //
    oldIrql = KeGetCurrentIrql();
    if (oldIrql < DISPATCH_LEVEL)
    {
        KeRaiseIrqlToDpcLevel();
    }

    //
    // Guest's RAX is overwritten by the host's value on #VMEXIT and saved in
    // the VMCB instead. Reflect the guest RAX to the context.
    //
    GuestRegisters->Rax = VpData->GuestVmcb.StateSaveArea.Rax;

    //
    // Update the _KTRAP_FRAME structure values in hypervisor stack, so that
    // Windbg can reconstruct call stack of the guest during debug session.
    // This is optional but very useful thing to do for debugging.
    //
    VpData->HostStackLayout.TrapFrame.Rsp = VpData->GuestVmcb.StateSaveArea.Rsp;
    VpData->HostStackLayout.TrapFrame.Rip = VpData->GuestVmcb.ControlArea.NRip;

    //
    // Default the TLB control to "no flush" each exit; specific handlers (NPT
    // toggles, the magic flush CPUID) set it to flush-all for this VMRUN only,
    // so a flush never lingers across subsequent VMRUNs.
    //
    VpData->GuestVmcb.ControlArea.TlbControl = 0;

    //
    // Handle #VMEXIT according with its reason.
    //
    switch (VpData->GuestVmcb.ControlArea.ExitCode)
    {
    case VMEXIT_VMMCALL:
        SvHandleVmmcall(VpData, &guestContext);
        break;
    case VMEXIT_MSR:
        SvHandleMsrAccess(VpData, &guestContext);
        break;
    case VMEXIT_VMRUN:
        SvHandleVmrun(VpData, &guestContext);
        break;
    case VMEXIT_EXCEPTION_DB:
        SvHandleDebugException(VpData);
        break;
    case VMEXIT_RDTSC:
        SvHandleRdtsc(VpData, &guestContext, FALSE);
        break;
    case VMEXIT_RDTSCP:
        SvHandleRdtsc(VpData, &guestContext, TRUE);
        break;
    case VMEXIT_NPF:
        if (SvHandleNestedPageFault(VpData, GuestRegisters) == FALSE)
        {
            //
            // A nested page fault we did not install (the map is a full identity
            // map, so this is unexpected). Treat as unrecoverable, as before.
            //
            SV_DEBUG_BREAK();
#pragma prefast(suppress : __WARNING_USE_OTHER_FUNCTION, "Unrecoverable path.")
            KeBugCheck(MANUALLY_INITIATED_CRASH);
        }
        break;
    default:
        SV_DEBUG_BREAK();
#pragma prefast(suppress : __WARNING_USE_OTHER_FUNCTION, "Unrecoverable path.")
        KeBugCheck(MANUALLY_INITIATED_CRASH);
    }

    //
    // Again, no effect to change IRQL but restoring it here since a #VMEXIT
    // handler where the developers most likely call the kernel API inadvertently
    // is already executed.
    //
    if (oldIrql < DISPATCH_LEVEL)
    {
        KeLowerIrql(oldIrql);
    }

    //
    // Terminate the hvsnap hypervisor if requested.
    //
    if (guestContext.ExitVm != FALSE)
    {
        NT_ASSERT(VpData->GuestVmcb.ControlArea.ExitCode == VMEXIT_VMMCALL);

        //
        // Set return values of the VMMCALL instruction as follows:
        //  RBX     = An address to return
        //  RCX     = A stack pointer to restore
        //  EDX:EAX = An address of per processor data to be freed by the caller
        //
        guestContext.VpRegs->Rax = reinterpret_cast<UINT64>(VpData) & MAXUINT32;
        guestContext.VpRegs->Rbx = VpData->GuestVmcb.ControlArea.NRip;
        guestContext.VpRegs->Rcx = VpData->GuestVmcb.StateSaveArea.Rsp;
        guestContext.VpRegs->Rdx = reinterpret_cast<UINT64>(VpData) >> 32;

        //
        // Load guest state (currently host state is loaded).
        //
        __svm_vmload(MmGetPhysicalAddress(&VpData->GuestVmcb).QuadPart);

        //
        // Set the global interrupt flag (GIF) but still disable interrupts by
        // clearing IF. GIF must be set to return to the normal execution, but
        // interruptions are not desirable until SVM is disabled as it would
        // execute random kernel-code in the host context.
        //
        _disable();
        __svm_stgi();

        //
        // Disable SVM, and restore the guest RFLAGS. This may enable interrupts.
        // Some of arithmetic flags are destroyed by the subsequent code.
        //
        __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) & ~EFER_SVME);
        __writeeflags(VpData->GuestVmcb.StateSaveArea.Rflags);
        goto Exit;
    }

    //
    // Reflect potentially updated guest's RAX to VMCB. Again, unlike other GPRs,
    // RAX is loaded from VMCB on VMRUN.
    //
    VpData->GuestVmcb.StateSaveArea.Rax = guestContext.VpRegs->Rax;

Exit:
    NT_ASSERT(VpData->HostStackLayout.Reserved1 == MAXUINT64);
    return guestContext.ExitVm;
}

/*!
    @brief      Returns attributes of a segment specified by the segment selector.

    @details    This function locates a segment descriptor from the segment
                selector and the GDT base, extracts attributes of the segment,
                and returns it. The returned value is the same as what the "dg"
                command of Windbg shows as "Flags". Here is an example output
                with 0x18 of the selector:
                ----
                0: kd> dg 18
                P Si Gr Pr Lo
                Sel        Base              Limit          Type    l ze an es ng Flags
                ---- ----------------- ----------------- ---------- - -- -- -- -- --------
                0018 00000000`00000000 00000000`00000000 Data RW Ac 0 Bg By P  Nl 00000493
                ----

    @param[in]  SegmentSelector - A segment selector to get attributes of a
                corresponding descriptor.
    @param[in]  GdtBase - A base address of GDT.

    @result     Attributes of the segment.
 */
_IRQL_requires_same_
_Check_return_
static
UINT16
SvGetSegmentAccessRight (
    _In_ UINT16 SegmentSelector,
    _In_ ULONG_PTR GdtBase
    )
{
    PSEGMENT_DESCRIPTOR descriptor;
    SEGMENT_ATTRIBUTE attribute;

    //
    // Get a segment descriptor corresponds to the specified segment selector.
    //
    descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(
                                        GdtBase + (SegmentSelector & ~RPL_MASK));

    //
    // Extract all attribute fields in the segment descriptor to a structure
    // that describes only attributes (as opposed to the segment descriptor
    // consists of multiple other fields).
    //
    attribute.Fields.Type = descriptor->Fields.Type;
    attribute.Fields.System = descriptor->Fields.System;
    attribute.Fields.Dpl = descriptor->Fields.Dpl;
    attribute.Fields.Present = descriptor->Fields.Present;
    attribute.Fields.Avl = descriptor->Fields.Avl;
    attribute.Fields.LongMode = descriptor->Fields.LongMode;
    attribute.Fields.DefaultBit = descriptor->Fields.DefaultBit;
    attribute.Fields.Granularity = descriptor->Fields.Granularity;
    attribute.Fields.Reserved1 = 0;

    return attribute.AsUInt16;
}

/*!
    @brief      Virtualizes the current processor.

    @details    This function enables SVM, initialize VMCB with the current
                processor state, and enters the guest mode on the current
                processor.

    @param[in,out]  VpData - The address of per processor data.
    @param[in]      SharedVpData - The address of share data.
    @param[in]      ContextRecord - The address of CONETEXT to use as an initial
                    context of the processor after it is virtualized.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
static
VOID
SvPrepareForVirtualization (
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData,
    _In_ const CONTEXT* ContextRecord
    )
{
    DESCRIPTOR_TABLE_REGISTER gdtr, idtr;
    PHYSICAL_ADDRESS guestVmcbPa, hostVmcbPa, hostStateAreaPa, pml4BasePa, msrpmPa;

    //
    // Capture the current GDTR and IDTR to use as initial values of the guest
    // mode.
    //
    _sgdt(&gdtr);
    __sidt(&idtr);

    guestVmcbPa = MmGetPhysicalAddress(&VpData->GuestVmcb);
    hostVmcbPa = MmGetPhysicalAddress(&VpData->HostVmcb);
    hostStateAreaPa = MmGetPhysicalAddress(&VpData->HostStateArea);
    pml4BasePa = MmGetPhysicalAddress(&SharedVpData->Pml4Entries);
    msrpmPa = MmGetPhysicalAddress(SharedVpData->MsrPermissionsMap);

    //
    // Configure to trigger #VMEXIT with VMMCALL and VMRUN instructions.
    //
    // CPUID is deliberately NOT intercepted: intercepting it would make every
    // guest CPUID take a #VMEXIT (~14x slower), which a target can trivially
    // detect by timing CPUID. The internal control signals that used to ride on
    // "magic CPUID leaves" (TLB flush, TSC-cloak on/off, unload) are now issued
    // via VMMCALL (SvHandleVmmcall) instead; VMMCALL is never executed by normal
    // code and is reflected as #UD for anything that is not our own request.
    //
    // VMRUN is intercepted because it is required by the processor to enter the
    // guest mode; otherwise, #VMEXIT occurs due to VMEXIT_INVALID when a
    // processor attempts to enter the guest mode. See "Canonicalization and
    // Consistency Checks" on "VMRUN Instruction".
    //
    VpData->GuestVmcb.ControlArea.InterceptMisc2 |=
        SVM_INTERCEPT_MISC2_VMRUN | SVM_INTERCEPT_MISC2_VMMCALL;

    //
    // Intercept the #DB (debug, vector 1) exception. Needed for the NPT
    // execute-trap's single-step-over: after letting one non-target instruction
    // run on the trapped page, the resulting #DB re-arms the No-Execute leaf.
    // #DB that is not one of ours is reflected back to the guest. The trigger
    // itself is the nested page fault (#NPF), enabled implicitly by nested
    // paging. See SvHandleNestedPageFault / SvHandleDebugException.
    //
    VpData->GuestVmcb.ControlArea.InterceptException |= (1UL << 1);

    //
    // Also, configure to trigger #VMEXIT on MSR access as configured by the
    // MSRPM. In our case, write to IA32_MSR_EFER is intercepted.
    //
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_MSR_PROT;
    VpData->GuestVmcb.ControlArea.MsrpmBasePa = msrpmPa.QuadPart;

    //
    // Specify guest's address space ID (ASID). TLB is maintained by the ID for
    // guests. Use the same value for all processors since all of them run a
    // single guest in our case. Use 1 as the most likely supported ASID by the
    // processor. The actual the supported number of ASID can be obtained with
    // CPUID. See "CPUID Fn8000_000A_EBX SVM Revision and Feature
    // Identification". Zero of ASID is reserved and illegal.
    //
    VpData->GuestVmcb.ControlArea.GuestAsid = 1;

    //
    // Enable Nested Page Tables. By enabling this, the processor performs the
    // nested page walk, that involves with an additional page walk to translate
    // a guest physical address to a system physical address. An address of
    // nested page tables is specified by the NCr3 field of VMCB.
    //
    // We have already build the nested page tables with SvBuildNestedPageTables.
    //
    // Note that our hypervisor does not trigger any additional #VMEXIT due to
    // the use of Nested Page Tables since all physical addresses from 0-512 GB
    // are configured to be accessible from the guest.
    //
    VpData->GuestVmcb.ControlArea.NpEnable |= SVM_NP_ENABLE_NP_ENABLE;
    VpData->GuestVmcb.ControlArea.NCr3 = pml4BasePa.QuadPart;

    //
    // Set up the initial guest state based on the current system state. Those
    // values are loaded into the processor as guest state when the VMRUN
    // instruction is executed.
    //
    VpData->GuestVmcb.StateSaveArea.GdtrBase = gdtr.Base;
    VpData->GuestVmcb.StateSaveArea.GdtrLimit = gdtr.Limit;
    VpData->GuestVmcb.StateSaveArea.IdtrBase = idtr.Base;
    VpData->GuestVmcb.StateSaveArea.IdtrLimit = idtr.Limit;

    VpData->GuestVmcb.StateSaveArea.CsLimit = GetSegmentLimit(ContextRecord->SegCs);
    VpData->GuestVmcb.StateSaveArea.DsLimit = GetSegmentLimit(ContextRecord->SegDs);
    VpData->GuestVmcb.StateSaveArea.EsLimit = GetSegmentLimit(ContextRecord->SegEs);
    VpData->GuestVmcb.StateSaveArea.SsLimit = GetSegmentLimit(ContextRecord->SegSs);
    VpData->GuestVmcb.StateSaveArea.CsSelector = ContextRecord->SegCs;
    VpData->GuestVmcb.StateSaveArea.DsSelector = ContextRecord->SegDs;
    VpData->GuestVmcb.StateSaveArea.EsSelector = ContextRecord->SegEs;
    VpData->GuestVmcb.StateSaveArea.SsSelector = ContextRecord->SegSs;
    VpData->GuestVmcb.StateSaveArea.CsAttrib = SvGetSegmentAccessRight(ContextRecord->SegCs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.DsAttrib = SvGetSegmentAccessRight(ContextRecord->SegDs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.EsAttrib = SvGetSegmentAccessRight(ContextRecord->SegEs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.SsAttrib = SvGetSegmentAccessRight(ContextRecord->SegSs, gdtr.Base);

    VpData->GuestVmcb.StateSaveArea.Efer = __readmsr(IA32_MSR_EFER);
    VpData->GuestVmcb.StateSaveArea.Cr0 = __readcr0();
    VpData->GuestVmcb.StateSaveArea.Cr2 = __readcr2();
    VpData->GuestVmcb.StateSaveArea.Cr3 = __readcr3();
    VpData->GuestVmcb.StateSaveArea.Cr4 = __readcr4();
    VpData->GuestVmcb.StateSaveArea.Rflags = ContextRecord->EFlags;
    VpData->GuestVmcb.StateSaveArea.Rsp = ContextRecord->Rsp;
    VpData->GuestVmcb.StateSaveArea.Rip = ContextRecord->Rip;
    VpData->GuestVmcb.StateSaveArea.GPat = __readmsr(IA32_MSR_PAT);

    //
    // Save some of the current state on VMCB. Some of those states are:
    // - FS, GS, TR, LDTR (including all hidden state)
    // - KernelGsBase
    // - STAR, LSTAR, CSTAR, SFMASK
    // - SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP
    // See "VMSAVE and VMLOAD Instructions" for mode details.
    //
    // Those are restored to the processor right before #VMEXIT with the VMLOAD
    // instruction so that the guest can start its execution with saved state,
    // and also, re-saved to the VMCS with right after #VMEXIT with the VMSAVE
    // instruction so that the host (hypervisor) do not destroy guest's state.
    //
    __svm_vmsave(guestVmcbPa.QuadPart);

    //
    // Store data to stack so that the host (hypervisor) can use those values.
    //
    VpData->HostStackLayout.Reserved1 = MAXUINT64;
    VpData->HostStackLayout.SharedVpData = SharedVpData;
    VpData->HostStackLayout.Self = VpData;
    VpData->HostStackLayout.HostVmcbPa = hostVmcbPa.QuadPart;
    VpData->HostStackLayout.GuestVmcbPa = guestVmcbPa.QuadPart;

    //
    // Set an address of the host state area to VM_HSAVE_PA MSR. The processor
    // saves some of the current state on VMRUN and loads them on #VMEXIT. See
    // "VM_HSAVE_PA MSR (C001_0117h)".
    //
    __writemsr(SVM_MSR_VM_HSAVE_PA, hostStateAreaPa.QuadPart);

    //
    // Also, save some of the current state to VMCB for the host. This is loaded
    // after #VMEXIT to reproduce the current state for the host (hypervisor).
    //
    __svm_vmsave(hostVmcbPa.QuadPart);
}

/*!
    @brief      Virtualize the current processor.

    @details    This function enables SVM, initialize VMCB with the current
                processor state, and enters the guest mode on the current
                processor.

    @param[in]  Context - A pointer of share data.

    @result     STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Check_return_
static
NTSTATUS
SvVirtualizeProcessor (
    _In_opt_ PVOID Context
    )
{
    NTSTATUS status;
    PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData;
    PVIRTUAL_PROCESSOR_DATA vpData;
    PCONTEXT contextRecord;
    ULONG cpu;

    SV_DEBUG_BREAK();

    vpData = nullptr;

    NT_ASSERT(ARGUMENT_PRESENT(Context));
    _Analysis_assume_(ARGUMENT_PRESENT(Context));

    contextRecord = static_cast<PCONTEXT>(ExAllocatePool2(
                                                        POOL_FLAG_NON_PAGED,
                                                        sizeof(*contextRecord),
                                                        'rtvh'));
    if (contextRecord == nullptr)
    {
        SvDebugPrint("Insufficient memory.\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Allocate per processor data.
    //
#pragma prefast(suppress : __WARNING_MEMORY_LEAK, "Ownership is taken on success.")
    vpData = static_cast<PVIRTUAL_PROCESSOR_DATA>(
            SvAllocatePageAlingedPhysicalMemory(sizeof(VIRTUAL_PROCESSOR_DATA)));
    if (vpData == nullptr)
    {
        SvDebugPrint("Insufficient memory.\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Record this processor (before the capture point) and mark it "not yet
    // virtualized". The two-pass RtlCaptureContext trick below uses this per-CPU
    // flag instead of the former CPUID self-check, because CPUID is no longer
    // intercepted (it now runs natively for stealth).
    //
    cpu = KeGetCurrentProcessorNumberEx(nullptr);
    if (cpu < HVSNAP_MAX_PROCESSORS)
    {
        g_CpuVirtualized[cpu] = 0;
    }

    //
    // Capture the current RIP, RSP, RFLAGS, and segment selectors. This
    // captured state is used as an initial state of the guest mode; therefore
    // when virtualization starts by the later call of SvLaunchVm, a processor
    // resume its execution at this location and state.
    //
    RtlCaptureContext(contextRecord);

    //
    // First pass (bare metal): the flag is 0, so virtualization is attempted.
    // After SvLaunchVm the processor resumes here as the guest with the flag set
    // to 1 (written just before VMRUN), so the branch is skipped and this
    // function returns STATUS_SUCCESS.
    //
    if ((cpu >= HVSNAP_MAX_PROCESSORS) || (g_CpuVirtualized[cpu] == 0))
    {
        SvDebugPrint("Attempting to virtualize the processor.\n");
        sharedVpData = static_cast<PSHARED_VIRTUAL_PROCESSOR_DATA>(Context);

        //
        // Enable SVM by setting EFER.SVME. It has already been verified that this
        // bit was writable with SvIsSvmSupported.
        //
        __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) | EFER_SVME);

        //
        // Set up VMCB, the structure describes the guest state and what events
        // within the guest should be intercepted, ie, triggers #VMEXIT.
        //
        SvPrepareForVirtualization(vpData, sharedVpData, contextRecord);

        //
        // Switch to the host RSP to run as the host (hypervisor), and then
        // enters loop that executes code as a guest until #VMEXIT happens and
        // handles #VMEXIT as the host.
        //
        // This function should never return to here.
        //
        // Mark this CPU virtualized BEFORE entering the guest. The guest resumes
        // at the RtlCaptureContext return point and reads this flag as 1, so it
        // does not attempt to virtualize a second time.
        //
        if (cpu < HVSNAP_MAX_PROCESSORS)
        {
            g_CpuVirtualized[cpu] = 1;
        }

        SvLaunchVm(&vpData->HostStackLayout.GuestVmcbPa);
        SV_DEBUG_BREAK();
#pragma prefast(suppress : __WARNING_USE_OTHER_FUNCTION, "Unrecoverble path.")
        KeBugCheck(MANUALLY_INITIATED_CRASH);
    }

    SvDebugPrint("The processor has been virtualized.\n");
    status = STATUS_SUCCESS;

Exit:
    if (contextRecord != nullptr)
    {
        ExFreePoolWithTag(contextRecord, 'rtvh');
    }
    if ((!NT_SUCCESS(status)) && (vpData != nullptr))
    {
        //
        // Frees per processor data if allocated and this function is
        // unsuccessful.
        //
        SvFreePageAlingedPhysicalMemory(vpData);
    }
    return status;
}

/*!
    @brief      Execute a callback on all processors one-by-one.

    @details    This function execute Callback with Context as a parameter for
                each processor on the current IRQL. If the callback returned
                non-STATUS_SUCCESS value or any error occurred, this function
                stops execution of the callback and returns the error code.

                When NumOfProcessorCompleted is not NULL, this function always
                set a number of processors that successfully executed the
                callback.

    @param[in]  Callback - A function to execute on all processors.
    @param[in]  Context - A parameter to pass to the callback.
    @param[out] NumOfProcessorCompleted - A pointer to receive a number of
                processors executed the callback successfully.

    @result     STATUS_SUCCESS when Callback executed and returned STATUS_SUCCESS
                on all processors; otherwise, an appropriate error code.
 */
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Check_return_
static
NTSTATUS
SvExecuteOnEachProcessor (
    _In_ NTSTATUS (*Callback)(PVOID),
    _In_opt_ PVOID Context,
    _Out_opt_ PULONG NumOfProcessorCompleted
    )
{
    NTSTATUS status;
    ULONG i, numOfProcessors;
    PROCESSOR_NUMBER processorNumber;
    GROUP_AFFINITY affinity, oldAffinity;

    status = STATUS_SUCCESS;

    //
    // Get a number of processors on this system.
    //
    numOfProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    for (i = 0; i < numOfProcessors; i++)
    {
        //
        // Convert from an index to a processor number.
        //
        status = KeGetProcessorNumberFromIndex(i, &processorNumber);
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }

        //
        // Switch execution of this code to a processor #i.
        //
        affinity.Group = processorNumber.Group;
        affinity.Mask = 1ULL << processorNumber.Number;
        affinity.Reserved[0] = affinity.Reserved[1] = affinity.Reserved[2] = 0;
        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

        //
        // Execute the callback.
        //
        status = Callback(Context);

        //
        // Revert the previously executed processor.
        //
        KeRevertToUserGroupAffinityThread(&oldAffinity);

        //
        // Exit if the callback returned error.
        //
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }
    }

Exit:
    //
    // i must be the same as the number of processors on the system when this
    // function returns STATUS_SUCCESS;
    //
    NT_ASSERT(!NT_SUCCESS(status) || (i == numOfProcessors));

    //
    // Set a number of processors that successfully executed callback if the
    // out parameter is present.
    //
    if (ARGUMENT_PRESENT(NumOfProcessorCompleted))
    {
        *NumOfProcessorCompleted = i;
    }
    return status;
}

/*!
    @brief      De-virtualize the current processor if virtualized.

    @details    This function asks hvsnap hypervisor to deactivate itself
                through CPUID with a back-door function id and frees per
                processor data if it is returned. If the hvsnap is not
                installed, this function does nothing.

    @param[in]  Context - An out pointer to receive an address of shared data.

    @result     Always STATUS_SUCCESS.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Check_return_
static
NTSTATUS
SvDevirtualizeProcessor (
    _In_opt_ PVOID Context
    )
{
    int registers[4];   // EAX, EBX, ECX, and EDX
    UINT64 high, low;
    PVIRTUAL_PROCESSOR_DATA vpData;
    PSHARED_VIRTUAL_PROCESSOR_DATA* sharedVpDataPtr;

    if (!ARGUMENT_PRESENT(Context))
    {
        goto Exit;
    }

    //
    // Ask the hvsnap hypervisor to deactivate itself via a VMMCALL (CPUID is no
    // longer intercepted). If the hypervisor is installed, the #VMEXIT handler's
    // ExitVm hand-off returns ECX='SSVM' and EDX:EAX = the per-processor data
    // address to free. On bare metal the VMMCALL is reflected as #UD (see below).
    //
    {
        ULONG cpu = KeGetCurrentProcessorNumberEx(nullptr);
        if (cpu < HVSNAP_MAX_PROCESSORS)
        {
            g_VmmcallReq[cpu] = HVREQ_UNLOAD;
        }
        __try
        {
            SvVmmcall(reinterpret_cast<unsigned int*>(registers));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            //
            // #UD -> not virtualized (nothing to devirtualize on this CPU).
            //
            goto Exit;
        }
    }
    if (registers[2] != 'SSVM')
    {
        goto Exit;
    }

    SvDebugPrint("The processor has been de-virtualized.\n");

    //
    // Get an address of per processor data indicated by EDX:EAX.
    //
    high = registers[3];
    low = registers[0] & MAXUINT32;
    vpData = reinterpret_cast<PVIRTUAL_PROCESSOR_DATA>(high << 32 | low);
    NT_ASSERT(vpData->HostStackLayout.Reserved1 == MAXUINT64);

    //
    // Save an address of shared data, then free per processor data.
    //
    sharedVpDataPtr = static_cast<PSHARED_VIRTUAL_PROCESSOR_DATA*>(Context);
    *sharedVpDataPtr = vpData->HostStackLayout.SharedVpData;
    SvFreePageAlingedPhysicalMemory(vpData);

Exit:
    return STATUS_SUCCESS;
}

/*!
    @brief      De-virtualize all virtualized processors.

    @details    This function execute a callback to de-virtualize a processor on
                all processors, and frees shared data when the callback returned
                its pointer from a hypervisor.
 */
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
static
VOID
SvDevirtualizeAllProcessors (
    VOID
    )
{
    PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData;

    sharedVpData = nullptr;

    //
    // De-virtualize all processors and free shared data when returned.
    //
    NT_VERIFY(NT_SUCCESS(SvExecuteOnEachProcessor(SvDevirtualizeProcessor,
                                                  &sharedVpData,
                                                  nullptr)));
    if (sharedVpData != nullptr)
    {
        g_SharedVpData = nullptr;
        SvFreeContiguousMemory(sharedVpData->MsrPermissionsMap);
        SvFreePageAlingedPhysicalMemory(sharedVpData);
    }
}

/*!
    @brief          Build the MSR permissions map (MSRPM).

    @details        This function sets up MSRPM to intercept to IA32_MSR_EFER,
                    as suggested in "Extended Feature Enable Register (EFER)"
                    ----
                    Secure Virtual Machine Enable (SVME) Bit
                    Bit 12, read/write. Enables the SVM extensions. (...) The
                    effect of turning off EFER.SVME while a guest is running is
                    undefined; therefore, the VMM should always prevent guests
                    from writing EFER.
                    ----

                    Each MSR is controlled by two bits in the MSRPM. The LSB of
                    the two bits controls read access to the MSR and the MSB
                    controls write access. A value of 1 indicates that the
                    operation is intercepted. This function locates an offset for
                    IA32_MSR_EFER and sets the MSB bit. For details of logic, see
                    "MSR Intercepts".

    @param[in,out]  MsrPermissionsMap - The MSRPM to set up.
 */
_IRQL_requires_same_
static
VOID
SvBuildMsrPermissionsMap (
    _Inout_ PVOID MsrPermissionsMap
    )
{
    constexpr UINT32 BITS_PER_MSR = 2;
    constexpr UINT32 SECOND_MSR_RANGE_BASE = 0xc0000000;
    constexpr UINT32 SECOND_MSRPM_OFFSET = 0x800 * CHAR_BIT;
    RTL_BITMAP bitmapHeader;
    ULONG offsetFrom2ndBase, offset;

    //
    // Setup and clear all bits, indicating no MSR access should be intercepted.
    //
    RtlInitializeBitMap(&bitmapHeader,
                        static_cast<PULONG>(MsrPermissionsMap),
                        SVM_MSR_PERMISSIONS_MAP_SIZE * CHAR_BIT
                        );
    RtlClearAllBits(&bitmapHeader);

    //
    // Compute an offset from the second MSR permissions map offset (0x800) for
    // IA32_MSR_EFER in bits. Then, add an offset until the second MSR
    // permissions map.
    //
    offsetFrom2ndBase = (IA32_MSR_EFER - SECOND_MSR_RANGE_BASE) * BITS_PER_MSR;
    offset = SECOND_MSRPM_OFFSET + offsetFrom2ndBase;

    //
    // Set the MSB bit indicating write accesses to the MSR should be intercepted.
    //
    RtlSetBits(&bitmapHeader, offset + 1, 1);
}

/*!
    @brief      Build pass-through style page tables used in nested paging.

    @details    This function build page tables used in Nested Page Tables. The
                page tables are used to translate from a guest physical address
                to a system physical address and pointed by the NCr3 field of
                VMCB, like the traditional page tables are pointed by CR3.

                The nested page tables built in this function are set to
                translate a guest physical address to the same system physical
                address. For example, guest physical address 0x1000 is
                translated into system physical address 0x1000.

                In order to save memory to build nested page tables, 2MB large
                pages are used (as opposed to the standard pages that describe
                translation only for 4K granularity. Also, only up to 1 TB of
                translation is built. 1GB huge pages are not used due to VMware
                not supporting this feature.

    @param[out] SharedVpData - Out buffer to build nested page tables.
 */
_IRQL_requires_same_
static
VOID
SvBuildNestedPageTables (
    _Out_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData
    )
{
    ULONG64 pdptBasePa, pdBasePa, translationPa;

    //
    // Build only two PML4 entries. Those entries have subtables that control up to
    // 1 TB physical memory. PFN points to a base physical address of the page
    // directory pointer table.
    //
    for (ULONG64 pml4Index = 0; pml4Index < 2; pml4Index++) {
        PPML4_ENTRY_2MB pml4e = &SharedVpData->Pml4Entries[pml4Index];
        PPML4E_TREE pml4eTree = &SharedVpData->Pml4eTrees[pml4Index];

        //
        // Set the US (User) bit of all nested page table entries to be translated
        // without #VMEXIT, as all guest accesses are treated as user accesses at
        // the nested level. Also, the RW (Write) bit of nested page table entries
        // that corresponds to guest page tables must be 1 since all guest page
        // table accesses are threated as write access. See "Nested versus Guest
        // Page Faults, Fault Ordering" for more details.
        //
        // Those settings do not lower security since permission checks are done
        // twice independently: based on guest page tables, and nested page tables.
        // See "Nested versus Guest Page Faults, Fault Ordering" for more details.
        //
        pdptBasePa = MmGetPhysicalAddress(&pml4eTree->PdptEntries).QuadPart;
        pml4e->Fields.PageFrameNumber = pdptBasePa >> PAGE_SHIFT;
        pml4e->Fields.Valid = 1;
        pml4e->Fields.Write = 1;
        pml4e->Fields.User = 1;

        //
        // One PML4 entry controls 512 page directory pointer entires.
        //
        for (ULONG64 pdptIndex = 0; pdptIndex < 512; pdptIndex++)
        {
            //
            // PFN points to a base physical address of the page directory table.
            //
            pdBasePa = MmGetPhysicalAddress(&pml4eTree->PdEntries[pdptIndex][0]).QuadPart;
            pml4eTree->PdptEntries[pdptIndex].Fields.PageFrameNumber = pdBasePa >> PAGE_SHIFT;
            pml4eTree->PdptEntries[pdptIndex].Fields.Valid = 1;
            pml4eTree->PdptEntries[pdptIndex].Fields.Write = 1;
            pml4eTree->PdptEntries[pdptIndex].Fields.User = 1;

            //
            // One page directory entry controls 512 page directory entries.
            //
            // We do not explicitly configure PAT in the NPT entry. The consequences
            // of this are: 1) pages whose PAT (Page Attribute Table) type is the
            // Write-Combining (WC) memory type could be treated as the
            // Write-Combining Plus (WC+) while it should be WC when the MTRR type is
            // either Write Protect (WP), Writethrough (WT) or Writeback (WB), and
            // 2) pages whose PAT type is Uncacheable Minus (UC-) could be treated
            // as Cache Disabled (CD) while it should be WC, when MTRR type is WC.
            //
            // While those are not desirable, this is acceptable given that 1) only
            // introduces additional cache snooping and associated performance
            // penalty, which would not be significant since WC+ still lets
            // processors combine multiple writes into one and avoid large
            // performance penalty due to frequent writes to memory without caching.
            // 2) might be worse but I have not seen MTRR ranges configured as WC
            // on testing, hence the unintentional UC- will just results in the same
            // effective memory type as what would be with UC.
            //
            // See "Memory Types" (7.4), for details of memory types,
            // "PAT-Register PA-Field Indexing", "Combining Guest and Host PAT Types",
            // and "Combining PAT and MTRR Types" for how the effective memory type
            // is determined based on Guest PAT type, Host PAT type, and the MTRR
            // type.
            //
            // The correct approach may be to look up the guest PTE and copy the
            // caching related bits (PAT, PCD, and PWT) when constructing NTP
            // entries for non RAM regions, so the combined PAT will always be the
            // same as the guest PAT type. This may be done when any issue manifests
            // with the current implementation.
            //
            for (ULONG64 pdIndex = 0; pdIndex < 512; pdIndex++)
            {
                //
                // PFN points to a base physical address of system physical address
                // to be translated from a guest physical address. Set the PS
                // (LargePage) bit to indicate that this is a large page and no
                // subtable exists.
                //
                translationPa = (pml4Index * 512 * 512) + (pdptIndex * 512) + pdIndex;
                pml4eTree->PdEntries[pdptIndex][pdIndex].Fields.PageFrameNumber = translationPa;
                pml4eTree->PdEntries[pdptIndex][pdIndex].Fields.Valid = 1;
                pml4eTree->PdEntries[pdptIndex][pdIndex].Fields.Write = 1;
                pml4eTree->PdEntries[pdptIndex][pdIndex].Fields.User = 1;
                pml4eTree->PdEntries[pdptIndex][pdIndex].Fields.LargePage = 1;
            }
        }
    }
}

/*!
    @brief      Test whether the current processor support the SVM feature.

    @details    This function tests whether the current processor has enough
                features to run hvsnap, especially about SVM features.

    @result     TRUE if the processor supports the SVM feature; otherwise, FALSE.
 */
_IRQL_requires_same_
_Check_return_
static
BOOLEAN
SvIsSvmSupported (
    VOID
    )
{
    BOOLEAN svmSupported;
    int registers[4];   // EAX, EBX, ECX, and EDX
    ULONG64 vmcr;

    svmSupported = FALSE;

    //
    // Test if the current processor is AMD one. An AMD processor should return
    // "AuthenticAMD" from CPUID function 0. See "Function 0h-Maximum Standard
    // Function Number and Vendor String".
    //
    __cpuid(registers, CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING);
    if ((registers[1] != 'htuA') ||
        (registers[3] != 'itne') ||
        (registers[2] != 'DMAc'))
    {
        goto Exit;
    }

    //
    // Test if the SVM feature is supported by the current processor. See
    // "Enabling SVM" and "CPUID Fn8000_0001_ECX Feature Identifiers".
    //
    __cpuid(registers, CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX);
    if ((registers[2] & CPUID_FN8000_0001_ECX_SVM) == 0)
    {
        goto Exit;
    }

    //
    // Test if the Nested Page Tables feature is supported by the current
    // processor. See "Enabling Nested Paging" and "CPUID Fn8000_000A_EDX SVM
    // Feature Identification".
    //
    __cpuid(registers, CPUID_SVM_FEATURES);
    if ((registers[3] & CPUID_FN8000_000A_EDX_NP) == 0)
    {
        goto Exit;
    }

    //
    // Test if the SVM feature can be enabled. When VM_CR.SVMDIS is set,
    // EFER.SVME cannot be 1; therefore, SVM cannot be enabled. When
    // VM_CR.SVMDIS is clear, EFER.SVME can be written normally and SVM can be
    // enabled. See "Enabling SVM".
    //
    vmcr = __readmsr(SVM_MSR_VM_CR);
    if ((vmcr & SVM_VM_CR_SVMDIS) != 0)
    {
        goto Exit;
    }

    svmSupported = TRUE;

Exit:
    return svmSupported;
}

/*!
    @brief      Virtualizes all processors on the system.

    @details    This function attempts to virtualize all processors on the
                system, and returns STATUS_SUCCESS if all processors are
                successfully virtualized. If any processor is not virtualized,
                this function de-virtualizes all processors and returns an error
                code.

    @result     STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Check_return_
static
NTSTATUS
SvVirtualizeAllProcessors (
    VOID
    )
{
    NTSTATUS status;
    PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData;
    ULONG numOfProcessorsCompleted;

    sharedVpData = nullptr;
    numOfProcessorsCompleted = 0;

    //
    // Test whether the current processor supports all required SVM features. If
    // not, exit as error.
    //
    if (SvIsSvmSupported() == FALSE)
    {
        SvDebugPrint("SVM is not fully supported on this processor.\n");
        status = STATUS_HV_FEATURE_UNAVAILABLE;
        goto Exit;
    }

    //
    // Allocate a data structure shared across all processors. This data is
    // page tables used for Nested Page Tables.
    //
#pragma prefast(suppress : __WARNING_MEMORY_LEAK, "Ownership is taken on success.")
    sharedVpData = static_cast<PSHARED_VIRTUAL_PROCESSOR_DATA>(
        SvAllocatePageAlingedPhysicalMemory(sizeof(SHARED_VIRTUAL_PROCESSOR_DATA)));
    if (sharedVpData == nullptr)
    {
        SvDebugPrint("Insufficient memory.\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Allocate MSR permissions map (MSRPM) onto contiguous physical memory.
    //
    sharedVpData->MsrPermissionsMap = SvAllocateContiguousMemory(
                                                    SVM_MSR_PERMISSIONS_MAP_SIZE);
    if (sharedVpData->MsrPermissionsMap == nullptr)
    {
        SvDebugPrint("Insufficient memory.\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Build nested page table and MSRPM.
    //
    SvBuildNestedPageTables(sharedVpData);
    SvBuildMsrPermissionsMap(sharedVpData->MsrPermissionsMap);

    //
    // Publish the shared NPT so the ARM/DISARM paths can edit nested page tables.
    //
    g_SharedVpData = sharedVpData;

    //
    // Execute SvVirtualizeProcessor on and virtualize each processor one-by-one.
    // How many processors were successfully virtualized is stored in the third
    // parameter.
    //
    // STATUS_SUCCESS is returned if all processor are successfully virtualized.
    // When any error occurs while virtualizing processors, this function does
    // not attempt to virtualize the rest of processor. Therefore, only part of
    // processors on the system may have been virtualized on error. In this case,
    // it is a caller's responsibility to clean-up (de-virtualize) such
    // processors.
    //
    status = SvExecuteOnEachProcessor(SvVirtualizeProcessor,
                                      sharedVpData,
                                      &numOfProcessorsCompleted);

Exit:
    if (!NT_SUCCESS(status))
    {
        //
        // On failure, after successful allocation of shared data.
        //
        if (numOfProcessorsCompleted != 0)
        {
            //
            // If one or more processors have already been virtualized,
            // de-virtualize any of those processors, and free shared data.
            //
            NT_ASSERT(sharedVpData != nullptr);
            SvDevirtualizeAllProcessors();
        }
        else
        {
            //
            // If none of processors has not been virtualized, simply free
            // shared data.
            //
            if (sharedVpData != nullptr)
            {
                g_SharedVpData = nullptr;
                if (sharedVpData->MsrPermissionsMap != nullptr)
                {
                    SvFreeContiguousMemory(sharedVpData->MsrPermissionsMap);
                }
                SvFreePageAlingedPhysicalMemory(sharedVpData);
            }
        }
    }
    return status;
}

/*!
    @brief      IRP_MJ_CREATE / IRP_MJ_CLOSE handler for the control device.

    @details    The controller opens \\.\hvsnap to send IOCTLs; nothing to do
                but succeed the open/close.

    @param[in]  DeviceObject - Unused.
    @param[in]  Irp - The create/close IRP.

    @result     STATUS_SUCCESS.
 */
_Use_decl_annotations_
static
NTSTATUS
SvDispatchCreateClose (
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*!
    @brief      IRP_MJ_DEVICE_CONTROL handler for the control device.

    @details    Implements the ARM / DISARM / QUERY contract in hvsnap_ioctl.h.
                ARM publishes a freeze-at-RIP session; DISARM ends it; QUERY lets
                the controller poll for a hit. All buffers are METHOD_BUFFERED.

    @param[in]  DeviceObject - Unused.
    @param[in,out]  Irp - The device-control IRP.

    @result     STATUS_SUCCESS or an appropriate error code.
 */
_Use_decl_annotations_
static
NTSTATUS
SvDispatchDeviceControl (
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
    )
{
    PIO_STACK_LOCATION irpSp;
    NTSTATUS status;
    ULONG code;
    ULONG inLength;
    ULONG outLength;
    ULONG_PTR information;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    inLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    information = 0;
    status = STATUS_INVALID_DEVICE_REQUEST;

    switch (code)
    {
    case HVSNAP_IOCTL_ARM:
        if (inLength >= sizeof(HVSNAP_ARM_REQUEST))
        {
            PHVSNAP_ARM_REQUEST request =
                static_cast<PHVSNAP_ARM_REQUEST>(Irp->AssociatedIrp.SystemBuffer);

            //
            // Install the NPT execute-trap. SvArmNptTrap resolves + pins the
            // target page, splits the covering 2MB PDE, marks the target leaf
            // No-Execute, and flushes every core's nested TLB.
            //
            //
            // Register-trace mode: allocate the capture ring BEFORE arming the
            // trap (so a #NPF never finds a half-initialized ring). If the ring
            // alloc fails, do not arm.
            //
            status = STATUS_SUCCESS;
            if (request->TraceEnabled != 0)
            {
                status = SvTraceStart(request->TraceRingBytes);
            }
            if (NT_SUCCESS(status))
            {
                status = SvArmNptTrap(request->TargetPid,
                                      request->TargetRip,
                                      request->ParkStubVa,
                                      &request->Predicate,
                                      request->HitSkip,
                                      (request->CloakTsc != 0) ? TRUE : FALSE);
                if (!NT_SUCCESS(status) && request->TraceEnabled != 0)
                {
                    SvTraceStop();      // arm failed - undo the ring
                }
            }
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case HVSNAP_IOCTL_DISARM:
        SvDisarmNptTrap();
        status = STATUS_SUCCESS;
        break;

    case HVSNAP_IOCTL_CLOAK_OFF:
        SvStopTscCloak();
        status = STATUS_SUCCESS;
        break;

    case HVSNAP_IOCTL_TRACE_DRAIN:
        status = SvTraceDrain(Irp->AssociatedIrp.SystemBuffer, outLength, &information);
        break;

    case HVSNAP_IOCTL_TRACE_STOP:
        SvTraceStop();
        status = STATUS_SUCCESS;
        break;

    case HVSNAP_IOCTL_RECHECK:
        if (outLength >= sizeof(HVSNAP_RECHECK_REPLY))
        {
            PHVSNAP_RECHECK_REPLY reply =
                static_cast<PHVSNAP_RECHECK_REPLY>(Irp->AssociatedIrp.SystemBuffer);
            status = SvRecheckNptTrap(reply);
            information = sizeof(HVSNAP_RECHECK_REPLY);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case HVSNAP_IOCTL_QUERY:
        if (outLength >= HVSNAP_STATE_V1_SIZE)
        {
            PHVSNAP_STATE state =
                static_cast<PHVSNAP_STATE>(Irp->AssociatedIrp.SystemBuffer);

            state->Active = static_cast<UINT32>(g_Target.Active);
            //
            // Report the READY flag, not the bare claim: HitReady is
            // published only after the full Hit* payload is written and
            // barriered, so a controller that sees Hit!=0 can immediately
            // read every appended field without a torn-read window.
            //
            state->Hit = static_cast<UINT32>(g_Target.HitReady);
            state->HitTid = g_Target.HitTid;
            state->TargetRip = g_Target.TargetRip;
            state->ParkedCount = static_cast<UINT64>(g_Target.ParkedCount);
            state->MatchCount = static_cast<UINT64>(g_Target.MatchCount);
            state->CloakActive = static_cast<UINT32>(g_Target.CloakActive);
            state->StolenTsc = static_cast<UINT64>(g_Target.StolenTsc);
            information = HVSNAP_STATE_V1_SIZE;
            //
            // Extended fields: filled progressively as the caller's buffer
            // allows (keeps every controller/driver generation combination
            // working; the driver reports exactly what fit). The v2 tier is
            // gated by HVSNAP_STATE_V2_SIZE (the size through HitCr8) so a
            // v2 controller keeps receiving the v2 fields against a v3
            // driver; the descriptor-table tier needs the full v3 struct.
            //
            if (outLength >= HVSNAP_STATE_V2_SIZE)
            {
                state->HitFsBase = static_cast<UINT64>(g_Target.HitFsBase);
                state->HitGsBase = static_cast<UINT64>(g_Target.HitGsBase);
                state->HitCr0 = static_cast<UINT64>(g_Target.HitCr0);
                state->HitCr2 = static_cast<UINT64>(g_Target.HitCr2);
                state->HitCr3 = static_cast<UINT64>(g_Target.HitCr3);
                state->HitCr4 = static_cast<UINT64>(g_Target.HitCr4);
                state->HitEfer = static_cast<UINT64>(g_Target.HitEfer);
                state->HitDr6 = static_cast<UINT64>(g_Target.HitDr6);
                state->HitDr7 = static_cast<UINT64>(g_Target.HitDr7);
                state->HitStar = static_cast<UINT64>(g_Target.HitStar);
                state->HitLStar = static_cast<UINT64>(g_Target.HitLStar);
                state->HitCStar = static_cast<UINT64>(g_Target.HitCStar);
                state->HitSfMask = static_cast<UINT64>(g_Target.HitSfMask);
                state->HitKernelGsBase = static_cast<UINT64>(g_Target.HitKernelGsBase);
                state->HitSysenterCs = static_cast<UINT64>(g_Target.HitSysenterCs);
                state->HitSysenterEsp = static_cast<UINT64>(g_Target.HitSysenterEsp);
                state->HitSysenterEip = static_cast<UINT64>(g_Target.HitSysenterEip);
                state->HitCpl = static_cast<UINT64>(g_Target.HitCpl);
                state->HitGPat = static_cast<UINT64>(g_Target.HitGPat);
                state->HitDbgCtl = static_cast<UINT64>(g_Target.HitDbgCtl);
                state->HitTscGuest = static_cast<UINT64>(g_Target.HitTscGuest);
                state->HitTscAux = static_cast<UINT64>(g_Target.HitTscAux);
                state->HitCr8 = static_cast<UINT64>(g_Target.HitCr8);
                information = HVSNAP_STATE_V2_SIZE;
                if (outLength >= sizeof(HVSNAP_STATE))
                {
                    state->HitGdtrBase = static_cast<UINT64>(g_Target.HitGdtrBase);
                    state->HitIdtrBase = static_cast<UINT64>(g_Target.HitIdtrBase);
                    state->HitLdtrBase = static_cast<UINT64>(g_Target.HitLdtrBase);
                    state->HitTrBase = static_cast<UINT64>(g_Target.HitTrBase);
                    state->HitGdtrLimit = static_cast<UINT32>(g_Target.HitGdtrLimit);
                    state->HitIdtrLimit = static_cast<UINT32>(g_Target.HitIdtrLimit);
                    state->HitLdtrLimit = static_cast<UINT32>(g_Target.HitLdtrLimit);
                    state->HitTrLimit = static_cast<UINT32>(g_Target.HitTrLimit);
                    state->HitLdtrAttrib = static_cast<UINT32>(g_Target.HitLdtrAttrib);
                    state->HitTrAttrib = static_cast<UINT32>(g_Target.HitTrAttrib);
                    state->HitLdtrSelector = static_cast<UINT16>(g_Target.HitLdtrSelector);
                    state->HitTrSelector = static_cast<UINT16>(g_Target.HitTrSelector);
                    state->Reserved2 = 0;
                    information = sizeof(HVSNAP_STATE);
                }
            }
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/*!
    @brief      An entry point of this driver.

    @param[in]  DriverObject - A driver object.
    @param[in]  RegistryPath - Unused.

    @result     STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
_Use_decl_annotations_
EXTERN_C
NTSTATUS
DriverEntry (
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    UNICODE_STRING objectName;
    OBJECT_ATTRIBUTES objectAttributes;
    PCALLBACK_OBJECT callbackObject;
    PVOID callbackRegistration;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;
    BOOLEAN symbolicLinkCreated;

    UNREFERENCED_PARAMETER(RegistryPath);

    SV_DEBUG_BREAK();

    callbackRegistration = nullptr;
    symbolicLinkCreated = FALSE;
    DriverObject->DriverUnload = SvDriverUnload;

    //
    // Create the control device (\Device\hvsnap) and its user-visible symbolic
    // link (\DosDevices\hvsnap -> \\.\hvsnap) so the privileged controller can
    // send ARM / DISARM / QUERY IOCTLs. FILE_DEVICE_SECURE_OPEN applies the
    // device's ACL to name-based opens.
    //
    DriverObject->MajorFunction[IRP_MJ_CREATE] = SvDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = SvDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SvDispatchDeviceControl;

    deviceName = RTL_CONSTANT_STRING(HVSNAP_DEVICE_NAME);
    symbolicLinkName = RTL_CONSTANT_STRING(HVSNAP_SYMLINK_NAME);

    status = IoCreateDevice(DriverObject,
                            0,
                            &deviceName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &g_DeviceObject);
    if (!NT_SUCCESS(status))
    {
        SvDebugPrint("Failed to create the control device (0x%08x).\n", status);
        goto Exit;
    }

    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        SvDebugPrint("Failed to create the symbolic link (0x%08x).\n", status);
        goto Exit;
    }
    symbolicLinkCreated = TRUE;

    //
    // Opts-in no-execute (NX) nonpaged pool when available for security. By
    // defining POOL_NX_OPTIN as 1 and calling this function, nonpaged pool
    // allocation by the ExAllocatePool family with the NonPagedPool flag
    // automatically allocates NX nonpaged pool on Windows 8 and later versions
    // of Windows, while on Windows 7 where NX nonpaged pool is unsupported,
    // executable nonpaged pool is returned as usual.
    //
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    //
    // Registers a power state callback (SvPowerCallbackRoutine) to handle
    // system sleep and resume to manage virtualization state.
    //
    // First, opens the \Callback\PowerState callback object provides
    // notification regarding power state changes. This is a system defined
    // callback object that was already created by Windows. To open a system
    // defined callback object, the Create parameter of ExCreateCallback must be
    // FALSE (and AllowMultipleCallbacks is ignore when the Create parameter is
    // FALSE).
    //
    objectName = RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
    objectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&objectName,
                                                      OBJ_CASE_INSENSITIVE);
    status = ExCreateCallback(&callbackObject, &objectAttributes, FALSE, TRUE);
    if (!NT_SUCCESS(status))
    {
        SvDebugPrint("Failed to open the power state callback object.\n");
        goto Exit;
    }

    //
    // Then, registers our callback. The open callback object must be
    // dereferenced.
    //
    callbackRegistration = ExRegisterCallback(callbackObject,
                                              SvPowerCallbackRoutine,
                                              nullptr);
    ObDereferenceObject(callbackObject);
    if (callbackRegistration == nullptr)
    {
        SvDebugPrint("Failed to register a power state callback.\n");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    //
    // Virtualize all processors on the system.
    //
    status = SvVirtualizeAllProcessors();

Exit:
    if (NT_SUCCESS(status))
    {
        //
        // On success, save the registration handle for un-registration.
        //
        NT_ASSERT(callbackRegistration);
        g_PowerCallbackRegistration = callbackRegistration;
    }
    else
    {
        //
        // On any failure, clean up stuff as needed.
        //
        if (callbackRegistration != nullptr)
        {
            ExUnregisterCallback(callbackRegistration);
        }
        if (symbolicLinkCreated != FALSE)
        {
            IoDeleteSymbolicLink(&symbolicLinkName);
        }
        if (g_DeviceObject != nullptr)
        {
            IoDeleteDevice(g_DeviceObject);
            g_DeviceObject = nullptr;
        }
    }
    return status;
}

/*!
    @brief      Driver unload callback.

    @details    This function de-virtualize all processors on the system.

    @param[in]  DriverObject - Unused.
 */
_Use_decl_annotations_
static
VOID
SvDriverUnload (
    PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING symbolicLinkName;

    UNREFERENCED_PARAMETER(DriverObject);

    SV_DEBUG_BREAK();

    //
    // If a trap is still armed, remove it first (restores the NPT and frees the
    // split table / MDL / process reference) while virtualization is still up so
    // the cross-core TLB flush can run.
    //
    SvDisarmNptTrap();

    //
    // Free the trace ring (disarm above already synchronized all cores, so no
    // core is mid-capture).
    //
    SvTraceStop();

    //
    // Remove any lingering TSC cloak (RDTSC/RDTSCP intercept) while cores are
    // still virtualized so the disable IPI can run.
    //
    SvStopTscCloak();

    //
    // Remove the control device and its symbolic link.
    //
    symbolicLinkName = RTL_CONSTANT_STRING(HVSNAP_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symbolicLinkName);
    if (g_DeviceObject != nullptr)
    {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = nullptr;
    }

    //
    // Unregister the power state callback.
    //
    NT_ASSERT(g_PowerCallbackRegistration);
    ExUnregisterCallback(g_PowerCallbackRegistration);

    //
    // De-virtualize all processors on the system.
    //
    SvDevirtualizeAllProcessors();
}

/*!
    @brief      PowerState callback routine.

    @details    This function de-virtualize all processors when the system is
                exiting system power state S0 (ie, the system is about to sleep
                etc), and virtualize all processors when the system has just
                reentered S0 (ie, the system has resume from sleep etc).

                Those operations are required because virtualization is cleared
                during sleep.

                For the meanings of parameters, see ExRegisterCallback in MSDN.

    @param[in]  CallbackContext - Unused.
    @param[in]  Argument1 - A PO_CB_XXX constant value.
    @param[in]  Argument2 - A value of TRUE or FALSE.
 */
_Use_decl_annotations_
static
VOID
SvPowerCallbackRoutine (
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2
    )
{
    UNREFERENCED_PARAMETER(CallbackContext);

    //
    // PO_CB_SYSTEM_STATE_LOCK of Argument1 indicates that a system power state
    // change is imminent.
    //
    if (Argument1 != reinterpret_cast<PVOID>(PO_CB_SYSTEM_STATE_LOCK))
    {
        goto Exit;
    }

    if (Argument2 != FALSE)
    {
        //
        // The system has just reentered S0. Re-virtualize all processors.
        //
        NT_VERIFY(NT_SUCCESS(SvVirtualizeAllProcessors()));
    }
    else
    {
        //
        // The system is about to exit system power state S0. De-virtualize all
        // processors.
        //
        SvDevirtualizeAllProcessors();
    }

Exit:
    return;
}
