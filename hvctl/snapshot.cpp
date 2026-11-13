/*!
    @file   snapshot.cpp

    @brief  Op1 implementation: cross-process Pinscan-format memory snapshot.

    @details
    Byte-for-byte port of the Pin tool's snapshot (MyPinTool/exec_tracker.cpp,
    utils.cpp) reading a frozen target from the outside. Substitutions:
        VirtualQuery      -> VirtualQueryEx(hProc)
        PIN_SafeCopy      -> ReadProcessMemory(hProc)
        VirtualProtect    -> VirtualProtectEx(hProc)
        Pin CONTEXT regs  -> GetThreadContext(hitTid) (RIP overridden to targetRip)
        REG_SEG_GS_BASE   -> TEB base via NtQueryInformationThread
    Text files are written in binary mode (LF newlines) exactly like the Pin tool.
 */
#include "snapshot.h"
#include <cstdio>
#include <cstdint>
#include <intrin.h>
#include <cstring>
#include <vector>
#include <sstream>
#include <algorithm>
#include <tlhelp32.h>

// Provenance stamped into each snapshot's hvtrace.json. Bump on format changes.
#define HVSNAP_SNAPSHOT_VERSION "1.0"

namespace
{

// ---- ntdll query bits (avoid winternl clashes; resolve dynamically) ----
typedef struct _CLIENT_ID_LOCAL { HANDLE UniqueProcess; HANDLE UniqueThread; } CLIENT_ID_LOCAL;

typedef struct _THREAD_BASIC_INFORMATION_LOCAL
{
    LONG      ExitStatus;
    PVOID     TebBaseAddress;
    CLIENT_ID_LOCAL ClientId;
    ULONG_PTR AffinityMask;
    LONG      Priority;
    LONG      BasePriority;
} THREAD_BASIC_INFORMATION_LOCAL;

typedef struct _PROCESS_BASIC_INFORMATION_LOCAL
{
    LONG      ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION_LOCAL;

typedef LONG (WINAPI *PFN_NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG (WINAPI *PFN_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

PVOID QueryTebBase(HANDLE hThread)
{
    static PFN_NtQueryInformationThread fn =
        reinterpret_cast<PFN_NtQueryInformationThread>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    if (fn == nullptr) { return nullptr; }
    THREAD_BASIC_INFORMATION_LOCAL tbi{};
    ULONG len = 0;
    if (fn(hThread, 0 /*ThreadBasicInformation*/, &tbi, sizeof(tbi), &len) < 0) { return nullptr; }
    return tbi.TebBaseAddress;
}

PVOID QueryPebBase(HANDLE hProc)
{
    static PFN_NtQueryInformationProcess fn =
        reinterpret_cast<PFN_NtQueryInformationProcess>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (fn == nullptr) { return nullptr; }
    PROCESS_BASIC_INFORMATION_LOCAL pbi{};
    ULONG len = 0;
    if (fn(hProc, 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), &len) < 0) { return nullptr; }
    return pbi.PebBaseAddress;
}

// ---- formatting helpers (match utils.cpp) ----

// Hex(a): "0x" + lowercase hex, no leading zeros. (utils.cpp:14)
std::string Hex(unsigned long long a)
{
    char b[32];
    _snprintf_s(b, sizeof(b), _TRUNCATE, "0x%llx", a);
    return std::string(b);
}

// ProtectToString(prot): decode the base protection (prot & 0xFF). Covers all 8
// Windows base protections; the trailing 'c' marks copy-on-write (WRITECOPY),
// which is how executable image sections (e.g. packed .text/.sbss) appear before
// they are written. (Extends exec_tracker.cpp:50, which only handled 6 and so
// mislabeled EXECUTE_WRITECOPY/WRITECOPY/NOACCESS regions as "---".)
std::string ProtectToString(unsigned long prot)
{
    switch (prot & 0xFF)
    {
    case PAGE_EXECUTE:           return "X";
    case PAGE_EXECUTE_READ:      return "RX";
    case PAGE_EXECUTE_READWRITE: return "RWX";
    case PAGE_EXECUTE_WRITECOPY: return "RWXc";
    case PAGE_READONLY:          return "R";
    case PAGE_READWRITE:         return "RW";
    case PAGE_WRITECOPY:         return "RWc";
    case PAGE_NOACCESS:          return "NA";
    default:                     return "---";
    }
}

// RegionTypeToString(type): IMG / PRV / MAP (exec_tracker.cpp:60)
std::string RegionTypeToString(unsigned long type)
{
    return (type == MEM_IMAGE) ? "IMG" : (type == MEM_PRIVATE) ? "PRV" : "MAP";
}

void EnsureDirectoryExists(const std::string& path)
{
    if (CreateDirectoryA(path.c_str(), nullptr) != 0) { return; }
    if (GetLastError() == ERROR_ALREADY_EXISTS) { return; }
    fprintf(stderr, "[!] CreateDirectory failed for '%s' err=%lu\n", path.c_str(), GetLastError());
}

bool WriteTextFile(const std::string& path, const std::string& text)
{
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "wb") != 0 || f == nullptr) { return false; }
    fwrite(text.data(), 1, text.size(), f);
    fclose(f);
    return true;
}

// Chunked cross-process dump. Returns true only if the full size was captured.
// (Mirrors utils.cpp:DumpMemoryToBinary with PIN_SafeCopy -> ReadProcessMemory.)
bool DumpMemoryToBinary(HANDLE hProc, const std::string& path, unsigned long long start, size_t size)
{
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "wb") != 0 || f == nullptr)
    {
        fprintf(stderr, "[!] Failed to open %s for memory dump.\n", path.c_str());
        return false;
    }

    const size_t CHUNK = 65536;
    std::vector<uint8_t> buf(CHUNK);
    size_t remaining = size;
    unsigned long long cur = start;

    while (remaining > 0)
    {
        size_t toRead = remaining < CHUNK ? remaining : CHUNK;
        SIZE_T got = 0;
        BOOL ok = ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(cur), buf.data(), toRead, &got);
        if (ok && got > 0) { fwrite(buf.data(), 1, got, f); }
        if (!ok || got < toRead) { break; }
        remaining -= got;
        cur += got;
    }

    fclose(f);
    return remaining == 0;
}

// Read a pointer-sized value from the target.
bool ReadPtr(HANDLE hProc, unsigned long long addr, unsigned long long* out)
{
    SIZE_T got = 0;
    return ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(addr), out, sizeof(*out), &got) &&
           got == sizeof(*out);
}

// Walk the whole committed user address space and dump each region + manifest.
// (Port of exec_tracker.cpp:DumpFullAddressSpace, gSnapshotFullMaxRegion == 0.)
void DumpFullAddressSpace(HANDLE hProc, const std::string& dir, const std::string& tag, DWORD tid)
{
    const unsigned long long kUserMax = 0x00007FFFFFFF0000ULL;

    std::ostringstream manifest;
    manifest << "snapshot_full tag=" << tag << " tid=" << (unsigned)tid << "\n";
    manifest << "max_region_cap=none\n\n";

    unsigned long long addr = 0;
    size_t regions = 0, dumped = 0, skippedBig = 0;
    unsigned long long bytesDumped = 0;

    while (addr < kUserMax)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) { break; }
        unsigned long long base = reinterpret_cast<unsigned long long>(mbi.BaseAddress);
        unsigned long long size = static_cast<unsigned long long>(mbi.RegionSize);
        if (size == 0) { break; }
        regions++;

        bool committed = (mbi.State == MEM_COMMIT);
        bool guarded   = (mbi.Protect & PAGE_GUARD) != 0;
        bool noaccess  = (mbi.Protect & 0xFF) == PAGE_NOACCESS;
        const char* stateStr = committed ? "COMMIT"
                             : (mbi.State == MEM_FREE) ? "FREE"
                             : (mbi.State == MEM_RESERVE) ? "RESERVE" : "OTHER";

        manifest << Hex(base) << " size=" << Hex(size)
                 << " state=" << stateStr
                 << " prot=" << ProtectToString(mbi.Protect) << "(" << Hex(mbi.Protect) << ")"
                 << " type=" << RegionTypeToString(mbi.Type)
                 << " allocbase=" << Hex(reinterpret_cast<unsigned long long>(mbi.AllocationBase));

        bool needUnlock = committed && (guarded || noaccess);
        if (committed)
        {
            DWORD oldProt = 0;
            bool unlocked = false;
            if (needUnlock)
            {
                unlocked = (VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize,
                                             PAGE_EXECUTE_READ, &oldProt) != 0);
            }
            char fn[400];
            _snprintf_s(fn, sizeof(fn), _TRUNCATE, "%s\\region_%llx_%llx_%s_%s.bin", dir.c_str(),
                        base, size, ProtectToString(mbi.Protect).c_str(),
                        RegionTypeToString(mbi.Type).c_str());
            bool ok = DumpMemoryToBinary(hProc, std::string(fn), base, static_cast<size_t>(size));
            if (unlocked)
            {
                DWORD tmp = 0;
                VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, oldProt, &tmp);
            }
            manifest << (ok ? (needUnlock ? " -> dumped(unlocked)" : " -> dumped")
                            : (needUnlock && !unlocked ? " -> SKIPPED(noaccess_unlock_failed)" : " -> partial"))
                     << " file=" << fn;
            dumped++;
            bytesDumped += size;
        }
        manifest << "\n";

        unsigned long long next = base + size;
        if (next <= addr) { break; }
        addr = next;
    }

    manifest << "\nregions_seen=" << regions
             << " regions_dumped=" << dumped
             << " regions_skipped_over_cap=" << skippedBig
             << " bytes_dumped=" << Hex(bytesDumped) << "\n";
    WriteTextFile(dir + "\\manifest.txt", manifest.str());

    printf("[*] snapshot_full %s: %zu/%zu committed regions dumped (%llx bytes) -> %s\\\n",
           tag.c_str(), dumped, regions, bytesDumped, dir.c_str());
}

// ---- hvtrace.json provenance ----

// Minimal JSON string escaper (backslashes in Windows paths, quotes, controls).
std::string JsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20)
            {
                char u[8];
                _snprintf_s(u, sizeof(u), _TRUNCATE, "\\u%04x", (unsigned)c);
                out += u;
            }
            else { out += static_cast<char>(c); }
        }
    }
    return out;
}

// ISO-8601 UTC timestamp, e.g. 2026-07-06T12:34:56Z.
std::string IsoTimestampUtc()
{
    SYSTEMTIME st{};
    GetSystemTime(&st);
    char b[32];
    _snprintf_s(b, sizeof(b), _TRUNCATE, "%04u-%02u-%02uT%02u:%02u:%02uZ",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::string(b);
}

// Full image path of the target (best-effort; empty on failure).
std::string QueryImagePath(HANDLE hProc)
{
    char buf[MAX_PATH * 2];
    DWORD sz = static_cast<DWORD>(sizeof(buf));
    if (QueryFullProcessImageNameA(hProc, 0, buf, &sz) && sz > 0)
    {
        return std::string(buf, sz);
    }
    return std::string();
}

// Find which loaded module contains 'addr' (Toolhelp; same-bitness target).
// Returns true and fills name/base/size when a containing module is found.
bool ResolveModuleForAddress(DWORD pid, unsigned long long addr,
                             std::string* name, unsigned long long* base, unsigned long long* size)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) { return false; }
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(snap, &me))
    {
        do
        {
            unsigned long long b = reinterpret_cast<unsigned long long>(me.modBaseAddr);
            unsigned long long e = b + me.modBaseSize;
            if (addr >= b && addr < e)
            {
                char nb[MAX_MODULE_NAME32 + 1] = {0};
                WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, nb, sizeof(nb), nullptr, nullptr);
                *name = std::string(nb);
                *base = b;
                *size = me.modBaseSize;
                found = true;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

// Write hvtrace.json: provenance the raw Pin dumps don't carry.
void WriteSnapshotJson(HANDLE hProc, DWORD pid, DWORD hitTid,
                       unsigned long long targetRip, const std::string& dir,
                       const std::string& tag, const std::string& prefix)
{
    std::string image = QueryImagePath(hProc);
    std::string modName;
    unsigned long long modBase = 0, modSize = 0;
    bool haveMod = ResolveModuleForAddress(pid, targetRip, &modName, &modBase, &modSize);

    std::ostringstream j;
    j << "{\n";
    j << "  \"hvtrace_version\": \"" << HVSNAP_SNAPSHOT_VERSION "\",\n";
    j << "  \"created_utc\": \"" << IsoTimestampUtc() << "\",\n";
    j << "  \"target\": {\n";
    j << "    \"pid\": " << (unsigned)pid << ",\n";
    j << "    \"image\": \"" << JsonEscape(image) << "\",\n";
    j << "    \"hit_tid\": " << (unsigned)hitTid << "\n";
    j << "  },\n";
    j << "  \"freeze\": {\n";
    j << "    \"rip\": \"" << Hex(targetRip) << "\",\n";
    if (haveMod)
    {
        j << "    \"module\": \"" << JsonEscape(modName) << "\",\n";
        j << "    \"module_base\": \"" << Hex(modBase) << "\",\n";
        j << "    \"module_size\": \"" << Hex(modSize) << "\",\n";
        j << "    \"module_offset\": \"" << Hex(targetRip - modBase) << "\"\n";
    }
    else
    {
        j << "    \"module\": null\n";
    }
    j << "  },\n";
    j << "  \"snapshot\": {\n";
    j << "    \"prefix\": \"" << JsonEscape(prefix) << "\",\n";
    j << "    \"tag\": \"" << JsonEscape(tag) << "\",\n";
    j << "    \"format\": \"pinscan_full\"\n";
    j << "  }\n";
    j << "}\n";
    WriteTextFile(dir + "\\hvtrace.json", j.str());
}

// ---- snapshot.ext.json: versioned extended-state sidecar ----
//
// Every component carries: value(s), provenance, and status. PROVENANCE is
// one of:
//   same_hit_guest        - read by the driver from the VMCB/exit context at
//                           the exact park event (the instruction boundary).
//   parked_thread_context - read from the frozen thread's user-mode CONTEXT
//                           (no target mutation; OS encoding, not raw XSAVE).
//   derived               - OS-convention assumption (never silently equal
//                           to measured; only in explicit fallbacks).
// STATUS is one of: present, absent (component not captured), unsupported
// (capture path exists but the OS/hardware refused or lacks the feature).
// Absent/unsupported NEVER substitutes zero for a measurement.
//
// v2 (2026-11-04, C review): adds "fp_state" - the parked x87/SSE values from
// the same GetThreadContext call that fills regs.txt, each field carrying its
// own provenance object. v1 carried these only as a prose note under xstate.
// Every fp_state value is byte-identical to the matching regs.txt row.
#define HVSNAP_EXT_SIDECAR_SCHEMA "slf.hvtrace.snapshot-ext.v2"

void WriteExtendedSidecar(HANDLE hProc, DWORD pid, DWORD hitTid,
                          unsigned long long targetRip, const std::string& dir,
                          const std::string& tag, const CONTEXT& parkedCtx,
                          unsigned long long mFsBase, unsigned long long mGsBase, bool haveBases,
                          unsigned long long mCr0, unsigned long long mCr2, unsigned long long mCr3,
                          unsigned long long mCr4, unsigned long long mEfer, bool haveControl,
                          unsigned long long mDr6, unsigned long long mDr7,
                          unsigned long long mStar, unsigned long long mLStar, unsigned long long mCStar,
                          unsigned long long mSfMask, unsigned long long mKernelGsBase,
                          unsigned long long mSysCs, unsigned long long mSysEsp, unsigned long long mSysEip,
                          unsigned long long mCpl, unsigned long long mGPat, unsigned long long mDbgCtl,
                          unsigned long long mTscGuest, unsigned long long mTscAux, unsigned long long mCr8,
                          bool haveExtended)
{
    std::ostringstream j;
    j << "{\n";
    j << "  \"schema\": \"" << HVSNAP_EXT_SIDECAR_SCHEMA << "\",\n";
    j << "  \"created_utc\": \"" << IsoTimestampUtc() << "\",\n";
    j << "  \"freeze_rip\": \"" << Hex(targetRip) << "\",\n";
    j << "  \"hit_tid\": " << (unsigned)hitTid << ",\n";

    // --- segment bases (driver-measured at the park event) ---
    j << "  \"segment_bases\": {\n";
    if (haveBases)
    {
        j << "    \"fs\": \"" << Hex(mFsBase) << "\", \"fs_provenance\": \"same_hit_guest\",\n";
        j << "    \"gs\": \"" << Hex(mGsBase) << "\", \"gs_provenance\": \"same_hit_guest\"\n";
    }
    else
    {
        j << "    \"status\": \"absent\",\n";
        j << "    \"note\": \"driver without measured-base support; legacy regs.txt derived values apply\"\n";
    }
    j << "  },\n";

    // --- control registers + system configuration (driver-measured) ---
    j << "  \"control_state\": {\n";
    if (haveControl)
    {
        j << "    \"cr0\": \"" << Hex(mCr0) << "\",\n";
        j << "    \"cr2\": \"" << Hex(mCr2) << "\",\n";
        j << "    \"cr3\": \"" << Hex(mCr3) << "\",\n";
        j << "    \"cr4\": \"" << Hex(mCr4) << "\",\n";
        j << "    \"efer\": \"" << Hex(mEfer) << "\",\n";
        // Derived decode of the geometry-relevant CR4 bits (labels, not new facts).
        j << "    \"cr4_decode\": {";
        j << "\"la57\": " << ((mCr4 >> 12) & 1) << ", ";
        j << "\"pcide\": " << ((mCr4 >> 17) & 1) << ", ";
        j << "\"smap\": " << ((mCr4 >> 21) & 1) << ", ";
        j << "\"smep\": " << ((mCr4 >> 20) & 1) << ", ";
        j << "\"osxsave\": " << ((mCr4 >> 18) & 1) << ", ";
        j << "\"osfxsr\": " << ((mCr4 >> 9) & 1) << ", ";
        j << "\"fsgsbase\": " << ((mCr4 >> 16) & 1);
        j << "},\n";
        j << "    \"provenance\": \"same_hit_guest\"\n";
    }
    else
    {
        j << "    \"status\": \"absent\"\n";
    }
    j << "  },\n";

    // --- same-hit VMCB system MSRs, guest debug, CPL, timing ---
    j << "  \"system_configuration\": {\n";
    if (haveExtended)
    {
        j << "    \"dr6\": \"" << Hex(mDr6) << "\", \"dr7\": \"" << Hex(mDr7) << "\",\n";
        j << "    \"star\": \"" << Hex(mStar) << "\", \"lstar\": \"" << Hex(mLStar) << "\",\n";
        j << "    \"cstar\": \"" << Hex(mCStar) << "\", \"sfmask\": \"" << Hex(mSfMask) << "\",\n";
        j << "    \"kernel_gs_base\": \"" << Hex(mKernelGsBase) << "\",\n";
        j << "    \"sysenter_cs\": \"" << Hex(mSysCs) << "\",\n";
        j << "    \"sysenter_esp\": \"" << Hex(mSysEsp) << "\", \"sysenter_eip\": \"" << Hex(mSysEip) << "\",\n";
        j << "    \"cpl\": " << (unsigned)mCpl << ",\n";
        j << "    \"gpat\": \"" << Hex(mGPat) << "\", \"dbgctl\": \"" << Hex(mDbgCtl) << "\",\n";
        j << "    \"provenance\": \"same_hit_guest\"\n";
    }
    else
    {
        j << "    \"status\": \"absent\"\n";
    }
    j << "  },\n";

    j << "  \"timing\": {\n";
    if (haveExtended)
    {
        j << "    \"tsc_guest_visible\": \"" << Hex(mTscGuest) << "\",\n";
        j << "    \"tsc_provenance\": \"same_hit_guest\",\n";
        j << "    \"tsc_aux\": \"" << Hex(mTscAux) << "\", \"tsc_aux_provenance\": \"same_hit_guest\",\n";
        j << "    \"cr8\": \"" << Hex(mCr8) << "\", \"cr8_provenance\": \"same_hit_guest\"\n";
    }
    else
    {
        j << "    \"status\": \"absent\"\n";
    }
    j << "  },\n";

    // --- parked x87/SSE state: field-level provenance in versioned data.
    //     Values are the SAME GetThreadContext reads that fill the regs.txt
    //     fctrl..st7 / mxcsr / xmm0-15 rows (byte-identical encodings); the
    //     OS encoding, not the raw XSAVE image. Every field names its source.
    j << "  \"fp_state\": {\n";
    {
        struct FpField { std::string name; std::string value; };
        auto bytes16hex = [](const void* p) {
            char hx[33];
            const unsigned char* raw = static_cast<const unsigned char*>(p);
            for (int b = 0; b < 16; ++b) { _snprintf_s(hx + b * 2, 3, _TRUNCATE, "%02x", (unsigned)raw[b]); }
            return std::string(hx);
        };
        std::vector<FpField> x87Fields = {
            {"fctrl", Hex((unsigned)parkedCtx.FltSave.ControlWord)},
            {"fstat", Hex((unsigned)parkedCtx.FltSave.StatusWord)},
            {"ftag",  Hex((unsigned)parkedCtx.FltSave.TagWord)},
            {"fop",   Hex((unsigned)parkedCtx.FltSave.ErrorOpcode)},
            {"fip",   Hex(parkedCtx.FltSave.ErrorOffset)},
            {"fcs",   Hex((unsigned)parkedCtx.FltSave.ErrorSelector)},
            {"fdp",   Hex(parkedCtx.FltSave.DataOffset)},
            {"fds",   Hex((unsigned)parkedCtx.FltSave.DataSelector)},
        };
        for (int st = 0; st < 8; ++st)
        {
            char name[8];
            _snprintf_s(name, sizeof(name), _TRUNCATE, "st%d", st);
            x87Fields.push_back({name, bytes16hex(&parkedCtx.FltSave.FloatRegisters[st])});
        }
        std::vector<FpField> sseFields = {
            {"mxcsr",      Hex((unsigned long long)parkedCtx.FltSave.MxCsr)},
            {"mxcsr_mask", Hex((unsigned long long)parkedCtx.FltSave.MxCsr_Mask)},
        };
        const M128A* xmm = &parkedCtx.Xmm0;   // contiguous Xmm0..Xmm15
        for (int i = 0; i < 16; ++i)
        {
            char name[8];
            _snprintf_s(name, sizeof(name), _TRUNCATE, "xmm%d", i);
            sseFields.push_back({name, bytes16hex(&xmm[i])});
        }
        auto emitGroup = [&j](const char* name, const std::vector<FpField>& fields, bool last) {
            j << "    \"" << name << "\": {\n";
            for (size_t i = 0; i < fields.size(); ++i)
            {
                j << "      \"" << fields[i].name << "\": {\"value\": \"" << fields[i].value
                  << "\", \"provenance\": \"parked_thread_context\"}" << (i + 1 < fields.size() ? "," : "") << "\n";
            }
            j << "    }" << (last ? "" : ",") << "\n";
        };
        j << "    \"status\": \"present\",\n";
        j << "    \"encoding\": \"windows_context_xsave_format\",\n";
        emitGroup("x87", x87Fields, false);
        emitGroup("sse", sseFields, false);
        j << "    \"note\": \"same GetThreadContext values as the regs.txt fctrl..st7/mxcsr/xmm rows; OS encoding, not the raw XSAVE image\"\n";
    }
    j << "  },\n";

    // --- CPUID leaves + XCR0 (hvctl-side, host-CPU enumeration; the guest
    //     executes on the same logical processors under hvsnap, so leaf
    //     data is CPU-fact; tagged distinctly from same-hit state) ---
    j << "  \"cpuid\": {\n";
    {
        int info[4];
        char brand[49] = {};
        __cpuid(info, 0x80000002);
        memcpy(brand + 0, info, 16);
        __cpuid(info, 0x80000003);
        memcpy(brand + 16, info, 16);
        __cpuid(info, 0x80000004);
        memcpy(brand + 32, info, 16);
        brand[48] = 0;
        j << "    \"brand\": \"" << JsonEscape(brand) << "\",\n";
        __cpuid(info, 1);
        j << "    \"leaf1_eax\": \"" << Hex((unsigned long long)(unsigned)info[0]) << "\",\n";
        j << "    \"leaf1_ecx\": \"" << Hex((unsigned long long)(unsigned)info[2]) << "\",\n";
        j << "    \"leaf1_edx\": \"" << Hex((unsigned long long)(unsigned)info[3]) << "\",\n";
        __cpuid(info, 7);
        j << "    \"leaf7_ebx\": \"" << Hex((unsigned long long)(unsigned)info[1]) << "\",\n";
        j << "    \"leaf7_ecx\": \"" << Hex((unsigned long long)(unsigned)info[2]) << "\",\n";
        j << "    \"leaf7_edx\": \"" << Hex((unsigned long long)(unsigned)info[3]) << "\",\n";
        __cpuidex(info, 0xd, 0);
        j << "    \"leafD_eax\": \"" << Hex((unsigned long long)(unsigned)info[0]) << "\",\n";
        // XCR0 via xgetbv (available when OSXSAVE; else absent).
        if (((mCr4 >> 18) & 1) || haveControl == false)
        {
            // host process must enable xgetbv usage: on Win it is permitted
            // when OSXSAVE set; _xgetbv intrinsic reads register 0.
            unsigned long long xcr0 = _xgetbv(0);
            j << "    \"xcr0\": \"" << Hex(xcr0) << "\",\n";
        }
        else
        {
            j << "    \"xcr0\": null,\n";
        }
        j << "    \"provenance\": \"host_cpu_enumeration\",\n";
        j << "    \"note\": \"CPU facts enumerated on the same logical processors the guest runs on; distinct from same-hit register state\"\n";
    }
    j << "  },\n";

    // --- XSAVE component status (what the OS reports enabled; full XSAVE
    //     image capture follows in a later schema revision as a binary blob;
    //     x87/SSE state already present in regs.txt via CONTEXT) ---
    j << "  \"xstate\": {\n";
    {
        unsigned long long xcr0 = _xgetbv(0);
        j << "    \"enabled_features\": \"" << Hex(xcr0) << "\",\n";
        j << "    \"x87\": " << ((xcr0 & 1) ? "true" : "false") << ",\n";
        j << "    \"sse\": " << ((xcr0 & 2) ? "true" : "false") << ",\n";
        j << "    \"avx\": " << ((xcr0 & 4) ? "true" : "false") << ",\n";
        j << "    \"avx512\": " << ((xcr0 & 0xe0) ? "true" : "false") << ",\n";
        j << "    \"full_image\": \"absent\",\n";
        j << "    \"provenance\": \"host_cpu_enumeration\",\n";
        j << "    \"note\": \"x87/SSE values with field-level provenance are in fp_state; YMM/ZMM upper halves and k-masks land with the full-image blob in a later revision\"\n";
    }
    j << "  },\n";

    // --- exception/unwind + VEH: static .pdata is inside the dumped module
    //     image regions; this section points at it and walks the dynamic
    //     vectored-handler chain (documented ntdll export RtlAddVectoredHandler
    //     keeps the list head in ntdll's data section - we locate handlers by
    //     scanning the loaded-module list only when a documented approach
    //     exists; otherwise absent, never guessed) ---
    j << "  \"exception_handling\": {\n";
    j << "    \"static_pdata\": \"present_in_module_regions\",\n";
    j << "    \"veh_chain\": \"absent\",\n";
    j << "    \"note\": \".pdata/.xdata are inside the dumped image bytes (region_14*_IMG dumps); dynamic VEH list discovery needs a documented walk - deferred rather than guessed\"\n";
    j << "  }\n";
    j << "}\n";
    WriteTextFile(dir + "\\snapshot.ext.json", j.str());
}

// ============================================================================
// v3 sidecar (snapshot.ext3.json, schema slf.hvtrace.snapshot-ext.v3)
//
// A SEPARATE artifact: the v2 sidecar above is frozen (byte-stable for the
// engine's intake) and is not modified by the v3 work. The v3 sidecar adds:
//   - cpu_identity:    leaf-0 vendor string + max leaves (measured, the seed
//                      the engine's vendor-law fragments key on) + the
//                      family/model/stepping decode of v2's leaf1_eax;
//   - tsc_calibration: leaves 0x15/0x16 (zeros => not enumerated, stated);
//   - descriptor_tables: GDTR/IDTR/LDTR/TR measured at the park event by the
//                      v3 driver tier (SGDT/SIDT/SLDT/STR ground truth);
//   - fp_state_upper:  XSAVE extended features past x87/SSE (YMM upper
//                      halves, k-masks, ZMM sections) via CONTEXT_XSTATE;
//   - integrity:       sha256 of every emitted file (self excluded).
// Absent is always reported, never zero-filled.
// ============================================================================

//
// Minimal FIPS 180-4 SHA-256 over a file, streaming in 64 KiB chunks.
// Returns the lowercase hex digest; empty string on any I/O failure.
//
static std::string Sha256File(const std::string& path)
{
    static const unsigned int K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
    unsigned int h[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                          0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    unsigned long long totalBits = 0;
    unsigned pending = 0;                     // carried partial-block bytes at buf front
    unsigned char buf[64 * 1024];

    HANDLE f = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) { return std::string(); }

    // K is a function-local static: reachable inside the lambda without
    // capture (only automatic locals need capturing; statics have fixed
    // addresses and capturing them is ill-formed).
    auto compress = [&h](const unsigned char* p) {
        unsigned int w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = ((unsigned)p[i*4] << 24) | ((unsigned)p[i*4+1] << 16) |
                   ((unsigned)p[i*4+2] << 8) | (unsigned)p[i*4+3];
        }
        for (int i = 16; i < 64; ++i) {
            unsigned int s0 = ((w[i-15] >> 7) | (w[i-15] << 25)) ^ ((w[i-15] >> 18) | (w[i-15] << 14)) ^ (w[i-15] >> 3);
            unsigned int s1 = ((w[i-2] >> 17) | (w[i-2] << 15)) ^ ((w[i-2] >> 19) | (w[i-2] << 13)) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        unsigned int a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f2=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            unsigned int S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7));
            unsigned int ch = (e & f2) ^ (~e & g);
            unsigned int t1 = hh + S1 + ch + K[i] + w[i];
            unsigned int S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10));
            unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
            unsigned int t2 = S0 + maj;
            hh=g; g=f2; f2=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f2; h[6]+=g; h[7]+=hh;
    };

    for (;;) {
        DWORD got = 0;
        if (!ReadFile(f, buf + pending, sizeof(buf) - pending, &got, nullptr)) {
            CloseHandle(f);
            return std::string();
        }
        if (got == 0) { break; }              // EOF
        unsigned avail = pending + got;
        totalBits += (unsigned long long)got * 8ull;
        unsigned whole = avail - (avail % 64);
        for (unsigned off = 0; off < whole; off += 64) { compress(buf + off); }
        pending = avail - whole;
        if (pending != 0) { memmove(buf, buf + whole, pending); }
    }
    CloseHandle(f);

    // Finalize: pending bytes + 0x80 + zero pad + 64-bit big-endian bit length.
    unsigned char tail[128];
    unsigned len = (pending + 9 <= 64) ? 64 : 128;
    memset(tail, 0, sizeof(tail));
    memcpy(tail, buf, pending);
    tail[pending] = 0x80;
    unsigned long long bits = totalBits;
    for (int i = 0; i < 8; ++i) { tail[len - 1 - i] = (unsigned char)(bits & 0xff); bits >>= 8; }
    for (unsigned off = 0; off < len; off += 64) { compress(tail + off); }

    char out[65];
    for (int i = 0; i < 8; ++i) { _snprintf_s(out + i * 8, 9, _TRUNCATE, "%08x", h[i]); }
    return std::string(out);
}

//
// One extended XSAVE feature read from the parked hit thread via
// CONTEXT_XSTATE + LocateXStateFeature (the documented accessor; no layout
// assumptions). Returns false when the feature is not enabled (xcr0) or the
// read fails - the sidecar then reports it absent.
//
static bool ReadXsaveFeature(DWORD hitTid, DWORD feature, std::vector<unsigned char>& out)
{
    unsigned long long xcr0 = _xgetbv(0);
    if (!(xcr0 & (1ull << feature))) { return false; }

    HANDLE th = OpenThread(THREAD_GET_CONTEXT, FALSE, hitTid);
    if (th == nullptr) { return false; }
    bool ok = false;
    PCONTEXT ctx = nullptr;
    DWORD ctxSize = 0;
    InitializeContext(nullptr, CONTEXT_XSTATE, &ctx, &ctxSize);
    // ^ size probe: fails with ERROR_INSUFFICIENT_BUFFER and fills ctxSize
    std::vector<unsigned char> buf(ctxSize == 0 ? sizeof(CONTEXT) * 2 : ctxSize);
    if (InitializeContext(buf.data(), CONTEXT_XSTATE, &ctx, &ctxSize) && ctx != nullptr)
    {
        if (SetXStateFeaturesMask(ctx, (1ull << feature) | 3ull /* legacy x87+SSE */) &&
            GetThreadContext(th, ctx))
        {
            ULONG len = 0;
            void* p = LocateXStateFeature(ctx, feature, &len);
            if (p != nullptr && len > 0)
            {
                const unsigned char* raw = static_cast<const unsigned char*>(p);
                out.assign(raw, raw + len);
                ok = true;
            }
        }
    }
    CloseHandle(th);
    return ok;
}

static std::string BytesToHex(const unsigned char* p, size_t n)
{
    std::string s;
    s.reserve(n * 2);
    char hx[3];
    for (size_t i = 0; i < n; ++i)
    {
        _snprintf_s(hx, sizeof(hx), _TRUNCATE, "%02x", (unsigned)p[i]);
        s += hx;
    }
    return s;
}

//
// The v3 sidecar writer. Called LAST, after every other snapshot file exists
// (integrity hashes them all; this file itself is excluded).
//
static void WriteExt3Sidecar(const std::string& dir,
                             unsigned long long targetRip,
                             DWORD hitTid,
                             const Ext3DescriptorTables& dt)
{
    std::ostringstream j;
    j << "{\n";
    j << "  \"schema\": \"slf.hvtrace.snapshot-ext.v3\",\n";
    j << "  \"created_utc\": \"" << IsoTimestampUtc() << "\",\n";
    j << "  \"freeze_rip\": \"" << Hex(targetRip) << "\",\n";
    j << "  \"hit_tid\": " << (unsigned)hitTid << ",\n";

    // --- cpu identity: leaf 0 (vendor string, max leaves) + leaf1 decode ---
    int id[4] = {};
    __cpuid(id, 0);
    unsigned maxLeaf = (unsigned)id[0];
    char vendor[13] = {};
    memcpy(vendor + 0, &id[1], 4);      // EBX
    memcpy(vendor + 4, &id[3], 4);      // EDX
    memcpy(vendor + 8, &id[2], 4);      // ECX
    int ext[4] = {};
    __cpuid(ext, 0x80000000);
    unsigned maxExtLeaf = (unsigned)ext[0];
    int l1[4] = {};
    __cpuid(l1, 1);
    unsigned eax1 = (unsigned)l1[0];
    unsigned stepping = eax1 & 0xF;
    unsigned model = (eax1 >> 4) & 0xF;
    unsigned family = (eax1 >> 8) & 0xF;
    unsigned extModel = (eax1 >> 16) & 0xF;   // EAX[19:16], NOT [15:12]
    unsigned extFamily = (eax1 >> 20) & 0xFF;
    if (family == 0xF) { family += extFamily; model |= (extModel << 4); }

    j << "  \"cpu_identity\": {\n";
    j << "    \"vendor\": \"" << vendor << "\",\n";
    j << "    \"vendor_hex\": \"" << BytesToHex((const unsigned char*)vendor, 12) << "\",\n";
    j << "    \"max_leaf\": " << maxLeaf << ", \"max_extended_leaf\": " << maxExtLeaf << ",\n";
    j << "    \"family\": " << family << ", \"model\": " << model << ", \"stepping\": " << stepping << ",\n";
    j << "    \"leaf1_eax\": \"" << Hex((unsigned long long)eax1) << "\",\n";
    j << "    \"provenance\": \"host_cpu_enumeration\",\n";
    j << "    \"note\": \"vendor/family/model/stepping decoded per the SDM; family/model shown in display form; leaf1_eax also appears in the v2 sidecar (cpuid.leaf1_eax)\"\n";
    j << "  },\n";

    // --- TSC calibration leaves (zeros mean not enumerated - stated, not guessed) ---
    int l15[4] = {}; __cpuid(l15, 0x15);
    int l16[4] = {}; __cpuid(l16, 0x16);
    bool have15 = l15[0] != 0 && l15[1] != 0;
    bool have16 = l16[0] != 0;
    j << "  \"tsc_calibration\": {\n";
    if (have15)
    {
        j << "    \"leaf15_core_clock_numerator\": " << (unsigned)l15[0] << ",\n";
        j << "    \"leaf15_ref_clock_denominator\": " << (unsigned)l15[1] << ",\n";
        if (l15[2] != 0) { j << "    \"leaf15_nominal_tsc_hz\": " << (unsigned)l15[2] << ",\n"; }
        else { j << "    \"leaf15_nominal_tsc_hz\": null,\n"; }
    }
    if (have16)
    {
        j << "    \"leaf16_base_mhz\": " << (unsigned)l16[0] << ",\n";
        if (l16[1] != 0) { j << "    \"leaf16_max_mhz\": " << (unsigned)l16[1] << ",\n"; }
        if (l16[2] != 0) { j << "    \"leaf16_bus_mhz\": " << (unsigned)l16[2] << ",\n"; }
    }
    if (!have15 && !have16)
    {
        j << "    \"status\": \"absent\",\n";
        j << "    \"note\": \"CPUID 0x15/0x16 not enumerated by this CPU\",\n";
    }
    j << "    \"provenance\": \"host_cpu_enumeration\"\n";
    j << "  },\n";

    // --- descriptor tables (v3 driver tier, same-hit) ---
    j << "  \"descriptor_tables\": {\n";
    if (dt.present)
    {
        j << "    \"gdtr\": { \"base\": \"" << Hex(dt.gdtr_base) << "\", \"limit\": " << dt.gdtr_limit << " },\n";
        j << "    \"idtr\": { \"base\": \"" << Hex(dt.idtr_base) << "\", \"limit\": " << dt.idtr_limit << " },\n";
        j << "    \"ldtr\": { \"selector\": \"" << Hex((unsigned long long)dt.ldtr_selector) << "\", \"base\": \""
          << Hex(dt.ldtr_base) << "\", \"limit\": " << dt.ldtr_limit
          << ", \"attrib\": \"" << Hex((unsigned long long)dt.ldtr_attrib) << "\" },\n";
        j << "    \"tr\": { \"selector\": \"" << Hex((unsigned long long)dt.tr_selector) << "\", \"base\": \""
          << Hex(dt.tr_base) << "\", \"limit\": " << dt.tr_limit
          << ", \"attrib\": \"" << Hex((unsigned long long)dt.tr_attrib) << "\" },\n";
        j << "    \"provenance\": \"same_hit_guest\",\n";
        j << "    \"note\": \"VMCB descriptor-cache view at the park event; base/limit are what SGDT/SIDT store, selectors what SLDT/STR store, attrib is the hidden descriptor-cache attribute word\"\n";
    }
    else
    {
        j << "    \"status\": \"absent\",\n";
        j << "    \"note\": \"driver without descriptor-table capture (pre-v3 tier); QUERY returned fewer bytes\"\n";
    }
    j << "  },\n";

    // --- XSAVE upper state: YMM upper halves (AVX), k-masks / ZMM (AVX-512) ---
    j << "  \"fp_state_upper\": {\n";
    {
        // name must be a std::string: a const char* would alias the loop-local
        // buffer and every row would print the last-written name.
        struct Up { std::string name; std::string value; };
        std::vector<Up> ups;
        std::vector<unsigned char> feat;
        std::string note = "x87/SSE (fctrl..st7, mxcsr, xmm0-15) is in the v2 sidecar fp_state; these are the XSAVE features beyond it";
        bool any = false;

        if (ReadXsaveFeature(hitTid, 2 /* XSTATE_AVX */, feat))   // 16 x 16B YMM uppers
        {
            any = true;
            for (int i = 0; i < 16 && (size_t)(i * 16 + 16) <= feat.size(); ++i)
            {
                char name[16];
                _snprintf_s(name, sizeof(name), _TRUNCATE, "ymm%d_upper", i);
                ups.push_back({name, BytesToHex(&feat[(size_t)i * 16], 16)});
            }
        }
        if (ReadXsaveFeature(hitTid, 5 /* AVX-512 opmask */, feat))   // 8 x 8B k0..k7
        {
            any = true;
            for (int i = 0; i < 8 && (size_t)(i * 8 + 8) <= feat.size(); ++i)
            {
                char name[8];
                _snprintf_s(name, sizeof(name), _TRUNCATE, "k%d", i);
                ups.push_back({name, BytesToHex(&feat[(size_t)i * 8], 8)});
            }
        }
        if (ReadXsaveFeature(hitTid, 6 /* AVX-512 ZMM0-15 upper */, feat))   // 16 x 32B
        {
            any = true;
            for (int i = 0; i < 16 && (size_t)(i * 32 + 32) <= feat.size(); ++i)
            {
                char name[16];
                _snprintf_s(name, sizeof(name), _TRUNCATE, "zmm%d_upper", i);
                ups.push_back({name, BytesToHex(&feat[(size_t)i * 32], 32)});
            }
        }
        if (ReadXsaveFeature(hitTid, 7 /* AVX-512 ZMM16-31 */, feat))   // 16 x 64B
        {
            any = true;
            for (int i = 16; i < 32 && (size_t)((i - 16) * 64 + 64) <= feat.size(); ++i)
            {
                char name[16];
                _snprintf_s(name, sizeof(name), _TRUNCATE, "zmm%d", i);
                ups.push_back({name, BytesToHex(&feat[(size_t)(i - 16) * 64], 64)});
            }
        }

        if (any)
        {
            for (size_t i = 0; i < ups.size(); ++i)
            {
                // every row ends with a separator: the encoding/provenance/note
                // lines follow as further keys of the same object
                j << "    \"" << ups[i].name << "\": { \"value\": \"" << ups[i].value
                  << "\", \"provenance\": \"parked_thread_context\" },\n";
            }
            j << "    \"encoding\": \"xsave_feature_bytes\",\n";
            j << "    \"provenance\": \"parked_thread_context\",\n";
            j << "    \"note\": \"" << note << "\"\n";
        }
        else
        {
            j << "    \"status\": \"absent\",\n";
            unsigned long long xcr0 = _xgetbv(0);
            if (!(xcr0 & 0x4ull)) { j << "    \"note\": \"AVX not enabled in XCR0 on this host (see v2 sidecar xstate); no extended features to read\"\n"; }
            else { j << "    \"note\": \"CONTEXT_XSTATE read failed for the parked thread\"\n"; }
        }
    }
    j << "  },\n";

    // --- integrity: sha256 of every emitted file (self excluded) ---
    j << "  \"integrity\": {\n";
    {
        std::vector<std::string> names;
        WIN32_FIND_DATAA fd;
        HANDLE find = FindFirstFileA((dir + "\\*").c_str(), &fd);
        if (find != INVALID_HANDLE_VALUE)
        {
            do {
                if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) { continue; }
                if (strcmp(fd.cFileName, "snapshot.ext3.json") == 0) { continue; }
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { continue; }
                names.push_back(fd.cFileName);
            } while (FindNextFileA(find, &fd));
            FindClose(find);
        }
        std::sort(names.begin(), names.end());

        unsigned long long totalBytes = 0;
        unsigned hashed = 0;
        std::ostringstream files;
        for (size_t i = 0; i < names.size(); ++i)
        {
            std::string sha = Sha256File(dir + "\\" + names[i]);
            if (sha.empty()) { continue; }
            unsigned long long sz = 0;
            HANDLE f = CreateFileA((dir + "\\" + names[i]).c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (f != INVALID_HANDLE_VALUE)
            {
                LARGE_INTEGER li{};
                if (GetFileSizeEx(f, &li)) { sz = (unsigned long long)li.QuadPart; }
                CloseHandle(f);
            }
            totalBytes += sz;
            ++hashed;
            files << "    { \"name\": \"" << names[i] << "\", \"bytes\": " << sz
                  << ", \"sha256\": \"" << sha << "\" }" << (i + 1 < names.size() ? "," : "") << "\n";
        }
        j << "    \"algorithm\": \"sha256\",\n";
        j << "    \"files\": [\n" << files.str() << "    ],\n";
        j << "    \"total_files\": " << hashed << ", \"total_bytes\": " << totalBytes << ",\n";
        j << "    \"note\": \"hashes every regular file in this snapshot directory except snapshot.ext3.json itself (this file is written last)\"\n";
    }
    j << "  }\n";
    j << "}\n";
    WriteTextFile(dir + "\\snapshot.ext3.json", j.str());
}

} // namespace

bool WriteSnapshot(HANDLE hProc,
                   DWORD targetPid,
                   DWORD hitTid,
                   unsigned long long targetRip,
                   const std::string& outDir,
                   const std::string& prefix,
                   unsigned long long measuredFsBase,
                   unsigned long long measuredGsBase,
                   bool haveMeasuredBases,
                   unsigned long long measuredCr0,
                   unsigned long long measuredCr2,
                   unsigned long long measuredCr3,
                   unsigned long long measuredCr4,
                   unsigned long long measuredEfer,
                   bool haveMeasuredControl,
                   unsigned long long measuredDr6,
                   unsigned long long measuredDr7,
                   unsigned long long measuredStar,
                   unsigned long long measuredLStar,
                   unsigned long long measuredCStar,
                   unsigned long long measuredSfMask,
                   unsigned long long measuredKernelGsBase,
                   unsigned long long measuredSysenterCs,
                   unsigned long long measuredSysenterEsp,
                   unsigned long long measuredSysenterEip,
                   unsigned long long measuredCpl,
                   unsigned long long measuredGPat,
                   unsigned long long measuredDbgCtl,
                   unsigned long long measuredTscGuest,
                   unsigned long long measuredTscAux,
                   unsigned long long measuredCr8,
                   bool haveMeasuredExtended,
                   const Ext3DescriptorTables& descriptorTables,
                   bool writeExt3)
{
    // tag = <prefix>_000_rip<rip>  (single snapshot per run => seq 0)
    char tagbuf[128];
    _snprintf_s(tagbuf, sizeof(tagbuf), _TRUNCATE, "%s_%03u_rip%llx", prefix.c_str(), 0u, targetRip);
    std::string tag(tagbuf);

    std::string dir = outDir.empty() ? ("snapshot_full_" + tag) : (outDir + "\\snapshot_full_" + tag);
    if (!outDir.empty()) { EnsureDirectoryExists(outDir); }
    EnsureDirectoryExists(dir);

    printf("[*] Snapshot at 0x%llx (%s) -> %s\\\n", targetRip, prefix.c_str(), dir.c_str());

    auto dumpName = [&](const char* what, unsigned long long addr, unsigned long long sz) {
        char b[420];
        _snprintf_s(b, sizeof(b), _TRUNCATE, "%s\\%s_%s_%llx_%llx.bin", dir.c_str(), tag.c_str(),
                    what, addr, sz);
        return std::string(b);
    };

    // --- open the hit thread and capture its full context ---
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, hitTid);
    if (hThread == nullptr)
    {
        fprintf(stderr, "[!] OpenThread(%lu) for snapshot failed (err %lu).\n", hitTid, GetLastError());
        return false;
    }

    alignas(16) CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(hThread, &ctx))
    {
        fprintf(stderr, "[!] GetThreadContext failed (err %lu).\n", GetLastError());
        CloseHandle(hThread);
        return false;
    }

    unsigned long long tebBase = reinterpret_cast<unsigned long long>(QueryTebBase(hThread));
    unsigned long long pebBase = reinterpret_cast<unsigned long long>(QueryPebBase(hProc));
    CloseHandle(hThread);

    // --- 1. register state (<tag>_regs.txt); RIP is the freeze point, not the stub ---
    {
        std::ostringstream regs;
        regs << "# pinscan snapshot register state\n";
        regs << "snap_rip=" << Hex(targetRip) << "\n";
        regs << "tid=" << (unsigned)hitTid << "\n";
        regs << "rax=" << Hex(ctx.Rax) << "\n";
        regs << "rbx=" << Hex(ctx.Rbx) << "\n";
        regs << "rcx=" << Hex(ctx.Rcx) << "\n";
        regs << "rdx=" << Hex(ctx.Rdx) << "\n";
        regs << "rsi=" << Hex(ctx.Rsi) << "\n";
        regs << "rdi=" << Hex(ctx.Rdi) << "\n";
        regs << "rbp=" << Hex(ctx.Rbp) << "\n";
        regs << "rsp=" << Hex(ctx.Rsp) << "\n";
        regs << "r8=" << Hex(ctx.R8) << "\n";
        regs << "r9=" << Hex(ctx.R9) << "\n";
        regs << "r10=" << Hex(ctx.R10) << "\n";
        regs << "r11=" << Hex(ctx.R11) << "\n";
        regs << "r12=" << Hex(ctx.R12) << "\n";
        regs << "r13=" << Hex(ctx.R13) << "\n";
        regs << "r14=" << Hex(ctx.R14) << "\n";
        regs << "r15=" << Hex(ctx.R15) << "\n";
        regs << "rip=" << Hex(targetRip) << "\n";
        regs << "rflags=" << Hex(ctx.EFlags) << "\n";
        regs << "seg_cs=" << Hex(ctx.SegCs) << "\n";
        regs << "seg_ss=" << Hex(ctx.SegSs) << "\n";
        regs << "seg_ds=" << Hex(ctx.SegDs) << "\n";
        regs << "seg_es=" << Hex(ctx.SegEs) << "\n";
        regs << "seg_fs=" << Hex(ctx.SegFs) << "\n";
        regs << "seg_gs=" << Hex(ctx.SegGs) << "\n";
        if (haveMeasuredBases)
        {
            // MEASURED by the driver from the VMCB state-save area of the
            // hitting thread at the park event (the exact instruction boundary).
            regs << "fs_base=" << Hex(measuredFsBase) << "\n";
            regs << "gs_base=" << Hex(measuredGsBase) << "\n";
            regs << "fs_base_provenance=measured\n";
            regs << "gs_base_provenance=measured\n";
        }
        else
        {
            // DERIVED (pre-extension driver or no hit): Win64 defaults. This
            // is an assumption about the target, never a measured fact; a
            // target using wrfsbase/wrgsbase would NOT be captured here.
            regs << "fs_base=" << Hex(0) << "\n";           // FS base is 0 in x64 user mode (derived)
            regs << "gs_base=" << Hex(tebBase) << "\n";     // GS base == TEB (derived)
            regs << "fs_base_provenance=derived\n";
            regs << "gs_base_provenance=derived\n";
        }
        regs << "mxcsr=" << Hex(ctx.MxCsr) << "\n";
        if (haveMeasuredControl)
        {
            // MEASURED control registers from the VMCB state-save area of the
            // same park event (user mode cannot observe these).
            regs << "cr0=" << Hex(measuredCr0) << "\n";
            regs << "cr2=" << Hex(measuredCr2) << "\n";
            regs << "cr3=" << Hex(measuredCr3) << "\n";
            regs << "cr4=" << Hex(measuredCr4) << "\n";
            regs << "efer=" << Hex(measuredEfer) << "\n";
            if (haveMeasuredExtended)
            {
                // Same-hit VMCB extras + exit-entry latches.
                regs << "dr6_vmcb=" << Hex(measuredDr6) << "\n";
                regs << "dr7_vmcb=" << Hex(measuredDr7) << "\n";
                regs << "star=" << Hex(measuredStar) << "\n";
                regs << "lstar=" << Hex(measuredLStar) << "\n";
                regs << "cstar=" << Hex(measuredCStar) << "\n";
                regs << "sfmask=" << Hex(measuredSfMask) << "\n";
                regs << "kernel_gs_base=" << Hex(measuredKernelGsBase) << "\n";
                regs << "sysenter_cs=" << Hex(measuredSysenterCs) << "\n";
                regs << "sysenter_esp=" << Hex(measuredSysenterEsp) << "\n";
                regs << "sysenter_eip=" << Hex(measuredSysenterEip) << "\n";
                regs << "cpl=" << Hex(measuredCpl) << "\n";
                regs << "gpat=" << Hex(measuredGPat) << "\n";
                regs << "dbgctl=" << Hex(measuredDbgCtl) << "\n";
                regs << "tsc_guest=" << Hex(measuredTscGuest) << "\n";
                regs << "tsc_aux=" << Hex(measuredTscAux) << "\n";
                regs << "cr8=" << Hex(measuredCr8) << "\n";
                regs << "extended_msrs_provenance=measured_vmcbsave\n";
                regs << "tsc_provenance=guest_visible_at_park\n";
                regs << "cr8_provenance=exit_entry_latch\n";
            }
            else
            {
                regs << "extended_msrs_provenance=absent\n";
            }
            regs << "control_regs_provenance=measured\n";
        }
        else
        {
            regs << "control_regs_provenance=absent\n";
            regs << "extended_msrs_provenance=absent\n";
        }
        // Debug address/breakpoint registers, measured from the same thread
        // context (CONTEXT_ALL includes the debug register subset).
        regs << "dr0=" << Hex(ctx.Dr0) << "\n";
        regs << "dr1=" << Hex(ctx.Dr1) << "\n";
        regs << "dr2=" << Hex(ctx.Dr2) << "\n";
        regs << "dr3=" << Hex(ctx.Dr3) << "\n";
        regs << "dr6=" << Hex(ctx.Dr6) << "\n";
        regs << "dr7=" << Hex(ctx.Dr7) << "\n";
        // x87 FPU state from the same parked-thread context (CONTEXT_ALL
        // includes the float area; no target mutation). Legacy layout.
        regs << "fctrl=" << Hex((unsigned)ctx.FltSave.ControlWord) << "\n";
        regs << "fstat=" << Hex((unsigned)ctx.FltSave.StatusWord) << "\n";
        regs << "ftag=" << Hex((unsigned)ctx.FltSave.TagWord) << "\n";
        regs << "fop=" << Hex((unsigned)ctx.FltSave.ErrorOpcode) << "\n";
        regs << "fip=" << Hex(ctx.FltSave.ErrorOffset) << "\n";
        regs << "fcs=" << Hex((unsigned)ctx.FltSave.ErrorSelector) << "\n";
        regs << "fdp=" << Hex(ctx.FltSave.DataOffset) << "\n";
        regs << "fds=" << Hex((unsigned)ctx.FltSave.DataSelector) << "\n";
        for (int st = 0; st < 8; ++st)
        {
            // x87 registers are 80-bit; emit the raw 16-byte legacy slot.
            const unsigned char* raw =
                reinterpret_cast<const unsigned char*>(&ctx.FltSave.FloatRegisters[st]);
            char hx[33];
            for (int b = 0; b < 16; ++b) { _snprintf_s(hx + b * 2, 3, _TRUNCATE, "%02x", (unsigned)raw[b]); }
            regs << "st" << st << "=" << hx << "\n";
        }

        const M128A* xmm = &ctx.Xmm0;   // Xmm0..Xmm15 are contiguous
        for (int i = 0; i < 16; ++i)
        {
            unsigned char raw[16];
            memcpy(raw, &xmm[i], 16);    // little-endian bytes
            char hx[33];
            for (int b = 0; b < 16; ++b) { _snprintf_s(hx + b * 2, 3, _TRUNCATE, "%02x", (unsigned)raw[b]); }
            regs << "xmm" << i << "=" << hx << "\n";
        }
        WriteTextFile(dir + "\\" + tag + "_regs.txt", regs.str());
    }

    // --- 2. TEB / PEB ---
    if (tebBase != 0)
    {
        DumpMemoryToBinary(hProc, dumpName("teb", tebBase, 0x2000), tebBase, 0x2000);
    }
    if (pebBase != 0)
    {
        DumpMemoryToBinary(hProc, dumpName("peb", pebBase, 0x1000), pebBase, 0x1000);
    }

    // --- 3. full stack (TEB+0x8 = StackBase, TEB+0x10 = StackLimit) ---
    if (tebBase != 0)
    {
        unsigned long long stackBase = 0, stackLimit = 0;
        ReadPtr(hProc, tebBase + 0x8, &stackBase);
        ReadPtr(hProc, tebBase + 0x10, &stackLimit);
        if (stackBase > stackLimit)
        {
            DumpMemoryToBinary(hProc, dumpName("stack", stackLimit, stackBase - stackLimit),
                               stackLimit, static_cast<size_t>(stackBase - stackLimit));
        }
    }

    // --- 3b. TLS (TEB+0x58 = ThreadLocalStoragePointer, TEB+0x1480 = TlsSlots[64]) ---
    if (tebBase != 0)
    {
        const unsigned long long kUserMax = 0x00007FFFFFFF0000ULL;
        unsigned long long tlsArray = 0;
        if (ReadPtr(hProc, tebBase + 0x58, &tlsArray) && tlsArray != 0)
        {
            DumpMemoryToBinary(hProc, dumpName("tls_ptrarray", tlsArray, 0x800), tlsArray, 0x800);
            int consecInvalid = 0;
            for (int i = 0; i < 256; ++i)
            {
                unsigned long long blk = 0;
                if (!ReadPtr(hProc, tlsArray + static_cast<unsigned long long>(i) * sizeof(blk), &blk)) { break; }
                bool valid = false;
                if (blk >= 0x10000 && blk < kUserMax && (blk & 0x7) == 0)
                {
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(blk), &mbi, sizeof(mbi)) &&
                        mbi.State == MEM_COMMIT &&
                        (mbi.Protect & PAGE_GUARD) == 0 &&
                        (mbi.Protect & 0xFF) != PAGE_NOACCESS)
                    {
                        unsigned long long regEnd = reinterpret_cast<unsigned long long>(mbi.BaseAddress) +
                                                    static_cast<unsigned long long>(mbi.RegionSize);
                        unsigned long long avail = (regEnd > blk) ? (regEnd - blk) : 0;
                        unsigned long long toDump = avail < 0x10000 ? avail : 0x10000;
                        if (toDump)
                        {
                            DumpMemoryToBinary(hProc, dumpName("tls_block", blk, toDump), blk,
                                               static_cast<size_t>(toDump));
                            valid = true;
                        }
                    }
                }
                if (valid) { consecInvalid = 0; }
                else if (++consecInvalid >= 4) { break; }
            }
        }
        DumpMemoryToBinary(hProc, dumpName("tls_slots", tebBase + 0x1480, 0x200), tebBase + 0x1480, 0x200);
    }

    // --- 4. whole committed address space + manifest ---
    DumpFullAddressSpace(hProc, dir, tag, hitTid);

    // --- 5. hvtrace.json provenance (pid, image, module+offset, timestamp, version) ---
    WriteSnapshotJson(hProc, targetPid, hitTid, targetRip, dir, tag, prefix);

    // --- 6. snapshot.ext.json: versioned extended-state sidecar ---
    WriteExtendedSidecar(hProc, targetPid, hitTid, targetRip, dir, tag, ctx,
                         measuredFsBase, measuredGsBase, haveMeasuredBases,
                         measuredCr0, measuredCr2, measuredCr3, measuredCr4,
                         measuredEfer, haveMeasuredControl,
                         measuredDr6, measuredDr7, measuredStar, measuredLStar,
                         measuredCStar, measuredSfMask, measuredKernelGsBase,
                         measuredSysenterCs, measuredSysenterEsp, measuredSysenterEip,
                         measuredCpl, measuredGPat, measuredDbgCtl,
                         measuredTscGuest, measuredTscAux, measuredCr8,
                         haveMeasuredExtended);

    // --- 7. snapshot.ext3.json: v3 extended-state sidecar. A SEPARATE file -
    //     the v2 sidecar above stays byte-stable. Written LAST so its
    //     integrity section hashes every other file in the directory. ---
    if (writeExt3)
    {
        WriteExt3Sidecar(dir, targetRip, hitTid, descriptorTables);
    }
    return true;
}
