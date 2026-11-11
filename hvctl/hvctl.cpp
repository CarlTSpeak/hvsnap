/*!
    @file   hvctl.cpp

    @brief  hvsnap user-mode controller (freeze-test build, NPT trigger).

    @details
    Drives the hvsnap kernel driver's guest-invisible freeze-at-RIP primitive:

      1. Resolve the target: --pid or --name; absolute --rip, or --module+--offset.
      2. VirtualAllocEx a "park stub" page (EB FE = jmp $) in the target.
      3. ARM the driver with {pid, rip, parkStubVa}. The DRIVER installs an NPT
         execute-trap on the target page (No-Execute in the nested page tables) --
         no bytes are modified in the target, so self-checksums pass, and the
         guest cannot see or remove the trap.
      4. Poll QUERY for the hit. On hit the driver has redirected the hitting
         thread's RIP to the park stub.
      5. Suspend EVERY thread in the target (consistent freeze).
      6. Wait for the operator, then RESTORE: fix the parked thread(s) RIP back to
         the target, DISARM (driver restores the NPT), resume all threads, free
         the stub.

    This build validates the freeze primitive; the full Pinscan-format memory
    snapshot (Op1) and debugger hand-off (Op2) are layered on once freeze is
    proven.

    Build (x64). Run ELEVATED (needs the driver device + full process access).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <tlhelp32.h>
#include <cstdio>
#include <vector>
#include <string>
#include <conio.h>

#include "..\\hvsnap\\hvsnap_ioctl.h"
#include "snapshot.h"

namespace
{

std::string Narrow(const std::wstring& w)
{
    if (w.empty()) { return std::string(); }
    int n = WideCharToMultiByte(CP_ACP, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_ACP, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

struct Options
{
    DWORD Pid = 0;
    std::wstring ProcName;
    std::wstring ModuleName;
    unsigned long long Rip = 0;
    unsigned long long Offset = 0;
    bool HaveRip = false;
    bool HaveOffset = false;
    unsigned TimeoutSec = 60;
    std::wstring OutDir;         // snapshot output base dir (default: cwd)
    std::wstring Prefix = L"hv"; // snapshot tag prefix
    int HoldSec = -1;            // freeze/debug: hold N s instead of waiting for Enter (-1 = Enter)
    std::wstring LaunchPath;     // if set: CreateProcess(CREATE_SUSPENDED) then arm before 1st instruction
    std::wstring LaunchArgs;     // (launch) command-line arguments passed to the launched exe
    bool Launch = false;

    // Conditional trigger (--when <reg><op><imm>, optional &mask) + --skip N.
    bool HaveWhen = false;
    unsigned WhenReg = 0;        // x86 GP index 0..15
    unsigned WhenOp = 0;         // HVSNAP_OP_*
    unsigned WhenSize = 8;       // operand width in bytes
    unsigned long long WhenImm = 0;
    unsigned long long WhenMask = 0;
    unsigned long long HitSkip = 0;
    std::wstring WhenText;       // original expression, for display
    bool Cloak = false;          // hide the freeze gap from the target's RDTSC/RDTSCP
    bool KeepFrozen = false;     // (snapshot) stay frozen after the dump instead of auto-thawing
    bool TerminateAfter = false; // (snapshot/freeze) terminate the target after the clean thaw
    bool Handoff = false;        // (snapshot) after the dump, hand off to a debugger at the RIP
    unsigned RingMb = 256;       // (trace) driver capture-ring size in MB
    int DurationSec = -1;        // (trace) seconds to trace (-1 = until Enter)
    unsigned long long MaxRecords = 0; // (trace) stop after N records (0 = unlimited)
};

void PrintUsage()
{
    wprintf(
        L"hvctl (NPT freeze-at-RIP)  --  freeze a process at an exact RIP\n\n"
        L"Usage:\n"
        L"  hvctl <freeze|snapshot> --pid <N> --rip <0xADDR> [options]\n"
        L"  hvctl <freeze|snapshot> --name <proc.exe> --module <mod.dll> --offset <0xN> [options]\n"
        L"  hvctl <freeze|snapshot> --launch \"<path.exe>\" --rip <0xADDR> [options]\n\n"
        L"Modes:\n"
        L"  freeze     freeze at the RIP, wait for Enter, then thaw\n"
        L"  snapshot   freeze at the RIP, write a Pinscan-format snapshot, then thaw\n"
        L"  debug      freeze at the RIP (thread suspended AT the RIP, trap removed),\n"
        L"             wait while you attach a debugger, then resume on Enter\n"
        L"  trace      log a register sample on every (optionally --when-gated) hit of the RIP\n"
        L"             WITHOUT freezing; stream to a .bin, then 'trace-tocsv' to CSV\n\n"
        L"Options:\n"
        L"  --pid N            target process id\n"
        L"  --name proc.exe    target by image name (first match)\n"
        L"  --launch \"exe\"     launch the exe SUSPENDED, arm the trap, then resume\n"
        L"                     (race-free way to catch init code that runs at startup)\n"
        L"  --args \"...\"       (launch) command-line arguments to pass to the launched exe\n"
        L"  --module mod.dll   module to resolve --offset against (in the target)\n"
        L"  --rip 0xADDR       absolute runtime address to break at\n"
        L"  --offset 0xN       offset from the module base\n"
        L"  --timeout N        seconds to wait for the hit (default 60)\n"
        L"  --out DIR          snapshot output base dir (default: current dir)\n"
        L"  --prefix NAME      snapshot tag prefix (default: hv)\n"
        L"  --when EXPR        conditional trigger: only freeze when EXPR holds at the RIP,\n"
        L"                     e.g. --when rcx==0x5  |  --when \"r10&0xff!=0\"  (ops: == != < > <= >=)\n"
        L"  --when-size N      operand width in bytes for --when (1/2/4/8, default 8)\n"
        L"  --skip N           skip the first N matching hits before freezing (default 0)\n"
        L"  --cloak            hide the freeze gap from the target's RDTSC/RDTSCP (anti-timing).\n"
        L"                     RDTSC is intercepted guest-wide until 'hvctl cloak-off' or unload.\n"
        L"  --keep-frozen      (snapshot) stay frozen after the dump (thaw on Enter) instead of\n"
        L"                     auto-resuming; combine with --hold N to stay frozen N seconds.\n"
        L"  --terminate-after  after the snapshot and clean thaw, TERMINATE the target process\n"
        L"                     instead of letting it continue running.\n"
        L"  --handoff          (snapshot) after the dump, hand off to a debugger AT the RIP\n"
        L"                     (removes the NPT trap, restores the RIP) -- snapshot + debug in one.\n"
        L"  --out FILE         (trace) output .bin path (default: trace.bin)\n"
        L"  --ring-mb N        (trace) driver capture-ring size in MB (default: 256)\n"
        L"  --duration N       (trace) seconds to trace (default: until a key is pressed)\n"
        L"  --max-records N    (trace) stop after N records (default: unlimited)\n\n"
        L"Commands:\n"
        L"  hvctl cloak-off              remove TSC cloaking (undo --cloak) w/o unloading the driver\n"
        L"  hvctl trace-tocsv IN OUT     convert a captured trace .bin to CSV\n\n"
        L"Run elevated. Load the driver first (load-hvsnap.ps1).\n");
}

unsigned long long ParseHex(const wchar_t* s)
{
    return _wcstoui64(s, nullptr, 0);
}

// Map a register name to its x86 GP encoding index (0..15). Returns false if unknown.
bool RegNameToIndex(const std::wstring& n, unsigned* out)
{
    static const wchar_t* kRegs[16] = {
        L"rax", L"rcx", L"rdx", L"rbx", L"rsp", L"rbp", L"rsi", L"rdi",
        L"r8",  L"r9",  L"r10", L"r11", L"r12", L"r13", L"r14", L"r15"
    };
    for (unsigned i = 0; i < 16; ++i)
    {
        if (n == kRegs[i]) { *out = i; return true; }
    }
    return false;
}

// Parse a --when expression: <reg>[&<mask>]<op><imm>, op in {==,!=,<=,>=,<,>}.
// Fills opt.WhenReg/WhenOp/WhenImm/WhenMask. Returns false on syntax error.
bool ParseWhen(const std::wstring& exprIn, Options& opt)
{
    // strip spaces so `rcx == 5` and `rcx==5` both work
    std::wstring e;
    for (wchar_t c : exprIn) { if (c != L' ' && c != L'\t') e += c; }
    if (e.empty()) { return false; }

    // operator: find the two-char forms first, then single-char
    static const struct { const wchar_t* s; unsigned op; } kOps[] = {
        { L"==", HVSNAP_OP_EQ }, { L"!=", HVSNAP_OP_NE },
        { L"<=", HVSNAP_OP_ULE }, { L">=", HVSNAP_OP_UGE },
        { L"<",  HVSNAP_OP_ULT }, { L">",  HVSNAP_OP_UGT },
    };
    size_t opPos = std::wstring::npos; size_t opLen = 0; unsigned op = 0;
    for (const auto& k : kOps)
    {
        size_t p = e.find(k.s);
        if (p != std::wstring::npos && (opPos == std::wstring::npos || p < opPos))
        {
            opPos = p; opLen = wcslen(k.s); op = k.op;
        }
    }
    if (opPos == std::wstring::npos) { return false; }

    std::wstring lhs = e.substr(0, opPos);
    std::wstring rhs = e.substr(opPos + opLen);
    if (lhs.empty() || rhs.empty()) { return false; }

    // lhs = <reg>[&<mask>]
    std::wstring regName = lhs;
    unsigned long long mask = 0;
    size_t amp = lhs.find(L'&');
    if (amp != std::wstring::npos)
    {
        regName = lhs.substr(0, amp);
        mask = _wcstoui64(lhs.substr(amp + 1).c_str(), nullptr, 0);
    }
    unsigned reg = 0;
    if (!RegNameToIndex(regName, &reg)) { return false; }

    opt.WhenReg = reg;
    opt.WhenOp = op;
    opt.WhenMask = mask;
    opt.WhenImm = _wcstoui64(rhs.c_str(), nullptr, 0);
    opt.WhenText = exprIn;
    opt.HaveWhen = true;
    return true;
}

DWORD FindPidByName(const std::wstring& name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { return 0; }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe))
    {
        do
        {
            if (_wcsicmp(pe.szExeFile, name.c_str()) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

unsigned long long FindModuleBase(DWORD pid, const std::wstring& moduleName)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) { return 0; }

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    unsigned long long base = 0;
    if (Module32FirstW(snap, &me))
    {
        do
        {
            if (_wcsicmp(me.szModule, moduleName.c_str()) == 0)
            {
                base = reinterpret_cast<unsigned long long>(me.modBaseAddr);
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

std::vector<DWORD> EnumThreadIds(DWORD pid)
{
    std::vector<DWORD> ids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { return ids; }

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == pid) { ids.push_back(te.th32ThreadID); }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return ids;
}

// Trace .bin file header (written by `trace`, consumed by `trace-tocsv`).
static const char kTraceMagic[8] = { 'H','V','T','R','R','E','C','1' };

// Convert a captured .bin trace to CSV (offline; not on the hot path).
int TraceToCsv(const std::wstring& inPath, const std::wstring& outPath)
{
    FILE* in = nullptr;
    if (_wfopen_s(&in, inPath.c_str(), L"rb") != 0 || in == nullptr)
    {
        wprintf(L"[!] Cannot open %s\n", inPath.c_str());
        return 1;
    }
    char magic[8] = {0};
    unsigned recSize = 0, reserved = 0;
    if (fread(magic, 1, 8, in) != 8 || fread(&recSize, 4, 1, in) != 1 ||
        fread(&reserved, 4, 1, in) != 1 ||
        memcmp(magic, kTraceMagic, 8) != 0 || recSize != sizeof(HVSNAP_RECORD))
    {
        wprintf(L"[!] %s is not a valid hvsnap trace (bad magic/record size).\n", inPath.c_str());
        fclose(in);
        return 1;
    }
    FILE* out = nullptr;
    if (_wfopen_s(&out, outPath.c_str(), L"wb") != 0 || out == nullptr)
    {
        wprintf(L"[!] Cannot create %s\n", outPath.c_str());
        fclose(in);
        return 1;
    }
    // 8 MB stdio buffer so millions of rows flush efficiently.
    static char obuf[8 << 20];
    setvbuf(out, obuf, _IOFBF, sizeof(obuf));

    fputs("hit_index,rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15,"
          "rip,rflags,cr3,fs_base,gs_base,cs,ss,ds,es,fs,gs\n", out);

    HVSNAP_RECORD r;
    unsigned long long rows = 0;
    while (fread(&r, sizeof(r), 1, in) == 1)
    {
        fprintf(out,
            "%llu,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,"
            "0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,"
            "0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,"
            "0x%x,0x%x,0x%x,0x%x,0x%x,0x%x\n",
            (unsigned long long)r.HitIndex,
            (unsigned long long)r.Rax, (unsigned long long)r.Rcx, (unsigned long long)r.Rdx,
            (unsigned long long)r.Rbx, (unsigned long long)r.Rsp, (unsigned long long)r.Rbp,
            (unsigned long long)r.Rsi, (unsigned long long)r.Rdi, (unsigned long long)r.R8,
            (unsigned long long)r.R9, (unsigned long long)r.R10, (unsigned long long)r.R11,
            (unsigned long long)r.R12, (unsigned long long)r.R13, (unsigned long long)r.R14,
            (unsigned long long)r.R15, (unsigned long long)r.Rip, (unsigned long long)r.Rflags,
            (unsigned long long)r.Cr3, (unsigned long long)r.FsBase, (unsigned long long)r.GsBase,
            (unsigned)r.Cs, (unsigned)r.Ss, (unsigned)r.Ds, (unsigned)r.Es,
            (unsigned)r.Fs, (unsigned)r.Gs);
        rows++;
    }
    fclose(in);
    fclose(out);
    wprintf(L"[+] Wrote %llu rows -> %s\n", rows, outPath.c_str());
    return 0;
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    // Unbuffered stdout so progress (e.g. the debug-handoff banner) is visible
    // immediately even when redirected to a file/pipe.
    setvbuf(stdout, nullptr, _IONBF, 0);

    // Standalone command: turn TSC cloaking off (remove the guest-wide RDTSC
    // intercept) without unloading the driver.
    if (argc >= 2 && _wcsicmp(argv[1], L"cloak-off") == 0)
    {
        HANDLE d = CreateFileW(HVSNAP_WIN32_NAME, GENERIC_READ | GENERIC_WRITE, 0,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (d == INVALID_HANDLE_VALUE)
        {
            wprintf(L"[!] Cannot open %s (err %lu). Is the driver loaded and are you elevated?\n",
                    HVSNAP_WIN32_NAME, GetLastError());
            return 1;
        }
        DWORD ret = 0;
        BOOL ok = DeviceIoControl(d, HVSNAP_IOCTL_CLOAK_OFF, nullptr, 0, nullptr, 0, &ret, nullptr);
        CloseHandle(d);
        wprintf(ok ? L"[+] TSC cloak removed (RDTSC/RDTSCP no longer intercepted).\n"
                   : L"[!] CLOAK_OFF failed (err %lu).\n", GetLastError());
        return ok ? 0 : 1;
    }

    // Standalone command: convert a captured .bin register trace to CSV (offline).
    if (argc >= 2 && _wcsicmp(argv[1], L"trace-tocsv") == 0)
    {
        if (argc < 4) { wprintf(L"Usage: hvctl trace-tocsv <in.bin> <out.csv>\n"); return 1; }
        return TraceToCsv(argv[2], argv[3]);
    }

    bool snapshotMode = false;
    bool debugMode = false;
    bool traceMode = false;
    if (argc >= 2 && _wcsicmp(argv[1], L"snapshot") == 0) { snapshotMode = true; }
    else if (argc >= 2 && _wcsicmp(argv[1], L"debug") == 0) { debugMode = true; }
    else if (argc >= 2 && _wcsicmp(argv[1], L"trace") == 0) { traceMode = true; }
    else if (!(argc >= 2 && _wcsicmp(argv[1], L"freeze") == 0)) { PrintUsage(); return 1; }

    Options opt;
    for (int i = 2; i < argc; ++i)
    {
        std::wstring a = argv[i];
        auto next = [&](const wchar_t** out) -> bool {
            if (i + 1 >= argc) { return false; }
            *out = argv[++i];
            return true;
        };
        const wchar_t* v = nullptr;
        if (a == L"--pid" && next(&v)) { opt.Pid = static_cast<DWORD>(wcstoul(v, nullptr, 0)); }
        else if (a == L"--name" && next(&v)) { opt.ProcName = v; }
        else if (a == L"--launch" && next(&v)) { opt.LaunchPath = v; opt.Launch = true; }
        else if (a == L"--args" && next(&v)) { opt.LaunchArgs = v; }
        else if (a == L"--module" && next(&v)) { opt.ModuleName = v; }
        else if (a == L"--rip" && next(&v)) { opt.Rip = ParseHex(v); opt.HaveRip = true; }
        else if (a == L"--offset" && next(&v)) { opt.Offset = ParseHex(v); opt.HaveOffset = true; }
        else if (a == L"--timeout" && next(&v)) { opt.TimeoutSec = static_cast<unsigned>(wcstoul(v, nullptr, 0)); }
        else if (a == L"--out" && next(&v)) { opt.OutDir = v; }
        else if (a == L"--prefix" && next(&v)) { opt.Prefix = v; }
        else if (a == L"--hold" && next(&v)) { opt.HoldSec = (int)wcstol(v, nullptr, 0); }
        else if (a == L"--when" && next(&v))
        {
            if (!ParseWhen(v, opt)) { wprintf(L"[!] Bad --when expression: %s\n", v); return 1; }
        }
        else if (a == L"--when-size" && next(&v)) { opt.WhenSize = (unsigned)wcstoul(v, nullptr, 0); }
        else if (a == L"--skip" && next(&v)) { opt.HitSkip = _wcstoui64(v, nullptr, 0); }
        else if (a == L"--cloak") { opt.Cloak = true; }
        else if (a == L"--keep-frozen") { opt.KeepFrozen = true; }
        else if (a == L"--terminate-after") { opt.TerminateAfter = true; }
        else if (a == L"--handoff") { opt.Handoff = true; }
        else if (a == L"--ring-mb" && next(&v)) { opt.RingMb = (unsigned)wcstoul(v, nullptr, 0); }
        else if (a == L"--duration" && next(&v)) { opt.DurationSec = (int)wcstol(v, nullptr, 0); }
        else if (a == L"--max-records" && next(&v)) { opt.MaxRecords = _wcstoui64(v, nullptr, 0); }
        else { wprintf(L"Unknown/incomplete arg: %s\n", a.c_str()); PrintUsage(); return 1; }
    }

    // --- cleanup-scoped state (declared before any 'goto cleanup') ---
    HANDLE dev  = INVALID_HANDLE_VALUE;
    HANDLE proc = nullptr;
    HANDLE hLaunchThread = nullptr;   // main thread of a --launch'd (suspended) process
    bool   launched = false;
    int    rc = 1;
    LPVOID parkStub = nullptr;
    bool   armed = false;
    SIZE_T n = 0;
    DWORD  hitTid = 0;
    DWORD  pid = 0;
    unsigned long long rip = 0;
    unsigned long long measuredFsBase = 0;
    unsigned long long measuredGsBase = 0;
    bool   haveMeasuredBases = false;
    unsigned long long measuredCr0 = 0, measuredCr2 = 0, measuredCr3 = 0;
    unsigned long long measuredCr4 = 0, measuredEfer = 0;
    bool   haveMeasuredControl = false;
    unsigned long long measuredDr6 = 0, measuredDr7 = 0;
    unsigned long long measuredStar = 0, measuredLStar = 0, measuredCStar = 0;
    unsigned long long measuredSfMask = 0, measuredKernelGsBase = 0;
    unsigned long long measuredSysenterCs = 0, measuredSysenterEsp = 0, measuredSysenterEip = 0;
    unsigned long long measuredCpl = 0, measuredGPat = 0, measuredDbgCtl = 0;
    unsigned long long measuredTscGuest = 0, measuredTscAux = 0, measuredCr8 = 0;
    bool   haveMeasuredExtended = false;

    // --- launch (CREATE_SUSPENDED) or resolve an existing PID ---
    if (opt.Launch)
    {
        // The process is created frozen at its very entry, before a single
        // instruction of user code (incl. the loader / packer stub) runs. We
        // arm the NPT trap while it is suspended, then resume -- so init code
        // that executes microseconds after start is caught with no race.
        std::wstring workdir = opt.LaunchPath;
        size_t slash = workdir.find_last_of(L"\\/");
        if (slash != std::wstring::npos) { workdir.resize(slash); } else { workdir.clear(); }

        // Command line: quoted exe path (argv[0]) followed by any --args verbatim.
        std::wstring cmd = L"\"" + opt.LaunchPath + L"\"";
        if (!opt.LaunchArgs.empty()) { cmd += L" " + opt.LaunchArgs; }
        std::vector<wchar_t> cmdbuf(cmd.begin(), cmd.end());
        cmdbuf.push_back(L'\0');

        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (!CreateProcessW(opt.LaunchPath.c_str(), cmdbuf.data(), nullptr, nullptr, FALSE,
                            CREATE_SUSPENDED, nullptr,
                            workdir.empty() ? nullptr : workdir.c_str(), &si, &pi))
        {
            wprintf(L"[!] CreateProcess(--launch '%ls') failed (err %lu).\n",
                    opt.LaunchPath.c_str(), GetLastError());
            return 1;
        }
        pid = pi.dwProcessId;
        proc = pi.hProcess;      // full-access handle; enough for VirtualAllocEx/RPM/etc.
        hLaunchThread = pi.hThread;
        launched = true;
        wprintf(L"[*] Launched SUSPENDED pid=%lu: %ls%ls%ls\n", pid, opt.LaunchPath.c_str(),
                opt.LaunchArgs.empty() ? L"" : L" ", opt.LaunchArgs.c_str());
    }
    else
    {
        pid = opt.Pid;
        if (pid == 0 && !opt.ProcName.empty()) { pid = FindPidByName(opt.ProcName); }
        if (pid == 0)
        {
            wprintf(L"[!] Could not resolve target PID (use --pid, --name, or --launch).\n");
            return 1;
        }
    }

    // --- resolve absolute RIP ---
    if (opt.HaveRip)
    {
        rip = opt.Rip;
    }
    else if (!opt.ModuleName.empty() && opt.HaveOffset)
    {
        // NB: under --launch the loader has not populated the module list at
        // CREATE_SUSPENDED, so --module/--offset is unreliable there -- use --rip.
        unsigned long long base = FindModuleBase(pid, opt.ModuleName);
        if (base == 0)
        {
            wprintf(L"[!] Module '%s' not found in pid %lu.\n", opt.ModuleName.c_str(), pid);
            goto cleanup;
        }
        rip = base + opt.Offset;
        wprintf(L"[*] Module %s base=0x%llx + offset=0x%llx -> rip=0x%llx\n",
                opt.ModuleName.c_str(), base, opt.Offset, rip);
    }
    else
    {
        wprintf(L"[!] Specify --rip, or --module + --offset.\n");
        goto cleanup;
    }

    wprintf(L"[*] Target pid=%lu rip=0x%llx\n", pid, rip);

    // --- open the driver device ---
    dev = CreateFileW(HVSNAP_WIN32_NAME, GENERIC_READ | GENERIC_WRITE, 0,
                      nullptr, OPEN_EXISTING, 0, nullptr);
    if (dev == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[!] Cannot open %s (err %lu). Is hvsnap.sys loaded and are you elevated?\n",
                HVSNAP_WIN32_NAME, GetLastError());
        goto cleanup;
    }

    // --- open the target (unless we already own the launched handle) ---
    if (!launched)
    {
        const DWORD access = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                             PROCESS_QUERY_INFORMATION;
        proc = OpenProcess(access, FALSE, pid);
        if (proc == nullptr)
        {
            wprintf(L"[!] OpenProcess(%lu) failed (err %lu).\n", pid, GetLastError());
            goto cleanup;
        }
    }

    // --- allocate the park stub (jmp $) in the target ---
    parkStub = VirtualAllocEx(proc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (parkStub == nullptr)
    {
        wprintf(L"[!] VirtualAllocEx(park stub) failed (err %lu).\n", GetLastError());
        goto cleanup;
    }
    {
        BYTE jmpSelf[2] = { 0xEB, 0xFE }; // jmp $
        if (!WriteProcessMemory(proc, parkStub, jmpSelf, sizeof(jmpSelf), &n) || n != sizeof(jmpSelf))
        {
            wprintf(L"[!] WriteProcessMemory(park stub) failed (err %lu).\n", GetLastError());
            goto cleanup;
        }
        FlushInstructionCache(proc, parkStub, sizeof(jmpSelf));
        wprintf(L"[*] Park stub at 0x%llx (jmp $)\n",
                reinterpret_cast<unsigned long long>(parkStub));
    }

    // --- ARM the driver (installs the NPT execute-trap; no bytes touched) ---
    {
        HVSNAP_ARM_REQUEST req{};
        req.TargetPid = pid;
        req.TargetRip = rip;
        req.ParkStubVa = reinterpret_cast<unsigned long long>(parkStub);
        if (opt.HaveWhen)
        {
            req.Predicate.Kind = HVSNAP_PRED_REG;
            req.Predicate.Reg = opt.WhenReg;
            req.Predicate.Op = opt.WhenOp;
            req.Predicate.Size = opt.WhenSize;
            req.Predicate.Imm = opt.WhenImm;
            req.Predicate.Mask = opt.WhenMask;
        }
        else
        {
            req.Predicate.Kind = HVSNAP_PRED_NONE;
        }
        req.HitSkip = opt.HitSkip;
        req.CloakTsc = opt.Cloak ? 1u : 0u;
        req.TraceEnabled = traceMode ? 1u : 0u;
        req.TraceRingBytes = static_cast<unsigned long long>(opt.RingMb) * 1024ull * 1024ull;
        DWORD ret = 0;
        if (!DeviceIoControl(dev, HVSNAP_IOCTL_ARM, &req, sizeof(req), nullptr, 0, &ret, nullptr))
        {
            wprintf(L"[!] IOCTL ARM failed (err %lu). (NPT trap install failed in the driver.)\n",
                    GetLastError());
            goto cleanup;
        }
        armed = true;
        if (opt.HaveWhen)
        {
            wprintf(L"[*] Conditional trigger: %s  (size=%u, skip=%llu)\n",
                    opt.WhenText.c_str(), opt.WhenSize, opt.HitSkip);
        }
        if (opt.Cloak)
        {
            wprintf(L"[*] TSC cloak ON: the freeze gap will be hidden from the target's "
                    L"RDTSC/RDTSCP.\n"
                    L"    (RDTSC is intercepted guest-wide until 'hvctl cloak-off' or driver "
                    L"unload.)\n");
        }
        wprintf(L"[*] Armed (NPT execute-trap). Waiting up to %us for the target to reach the RIP...\n",
                opt.TimeoutSec);
    }

    // --- launch mode: release the suspended target now that the trap is armed.
    //     The process starts from its entry with the trap already in place, so
    //     init code at the target RIP is caught on its first execution. ---
    if (launched)
    {
        wprintf(L"[*] Resuming launched target (trap armed before any code ran)...\n");
        if (ResumeThread(hLaunchThread) == (DWORD)-1)
        {
            wprintf(L"[!] ResumeThread failed (err %lu).\n", GetLastError());
            goto cleanup;
        }
    }

    // --- trace mode: stream captured register records to a .bin, then stop ---
    if (traceMode)
    {
        std::wstring binPath = opt.OutDir.empty() ? L"trace.bin" : opt.OutDir;
        FILE* bin = nullptr;
        if (_wfopen_s(&bin, binPath.c_str(), L"wb") != 0 || bin == nullptr)
        {
            wprintf(L"[!] Cannot create trace file %ls\n", binPath.c_str());
            goto cleanup;
        }
        {
            unsigned recSize = static_cast<unsigned>(sizeof(HVSNAP_RECORD)), reserved = 0;
            fwrite(kTraceMagic, 1, sizeof(kTraceMagic), bin);
            fwrite(&recSize, sizeof(recSize), 1, bin);
            fwrite(&reserved, sizeof(reserved), 1, bin);
        }

        std::vector<unsigned char> drainBuf(16u << 20);   // 16 MB per drain
        unsigned long long totalRecords = 0, totalDropped = 0;
        const DWORD startTick = GetTickCount();
        const DWORD deadline = (opt.DurationSec >= 0)
                                   ? (startTick + static_cast<DWORD>(opt.DurationSec) * 1000)
                                   : 0;
        DWORD lastReport = startTick;

        wprintf(L"[*] TRACE running -> %ls  (ring=%u MB)\n", binPath.c_str(), opt.RingMb);
        if (opt.DurationSec >= 0) { wprintf(L"    duration=%ds", opt.DurationSec); }
        else                      { wprintf(L"    press any key to stop"); }
        if (opt.MaxRecords)       { wprintf(L", max-records=%llu", opt.MaxRecords); }
        wprintf(L"\n");

        bool stop = false;
        while (!stop)
        {
            DWORD outLen = 0;
            bool idle = true;
            if (DeviceIoControl(dev, HVSNAP_IOCTL_TRACE_DRAIN, nullptr, 0,
                                drainBuf.data(), static_cast<DWORD>(drainBuf.size()), &outLen, nullptr) &&
                outLen >= sizeof(HVSNAP_DRAIN_HEADER))
            {
                auto* h = reinterpret_cast<HVSNAP_DRAIN_HEADER*>(drainBuf.data());
                if (h->RecordCount > 0)
                {
                    fwrite(drainBuf.data() + sizeof(HVSNAP_DRAIN_HEADER),
                           sizeof(HVSNAP_RECORD), h->RecordCount, bin);
                    totalRecords += h->RecordCount;
                    idle = false;
                }
                totalDropped = h->TotalDropped;
                if (h->MoreAvailable) { idle = false; }
            }
            if (idle) { Sleep(1); }

            DWORD now = GetTickCount();
            if (now - lastReport >= 1000)
            {
                wprintf(L"\r[*] captured=%llu  dropped=%llu    ", totalRecords, totalDropped);
                lastReport = now;
            }

            if (opt.MaxRecords != 0 && totalRecords >= opt.MaxRecords) { stop = true; }
            if (deadline != 0 && GetTickCount() >= deadline) { stop = true; }
            if (deadline == 0 && _kbhit()) { (void)_getch(); stop = true; }
        }

        wprintf(L"\n[*] Stopping trace (disarm + final drain)...\n");
        {
            DWORD r2 = 0;
            DeviceIoControl(dev, HVSNAP_IOCTL_DISARM, nullptr, 0, nullptr, 0, &r2, nullptr);
            armed = false;
        }
        for (;;)
        {
            DWORD outLen = 0;
            if (!DeviceIoControl(dev, HVSNAP_IOCTL_TRACE_DRAIN, nullptr, 0,
                                 drainBuf.data(), static_cast<DWORD>(drainBuf.size()), &outLen, nullptr) ||
                outLen < sizeof(HVSNAP_DRAIN_HEADER))
            {
                break;
            }
            auto* h = reinterpret_cast<HVSNAP_DRAIN_HEADER*>(drainBuf.data());
            if (h->RecordCount > 0)
            {
                fwrite(drainBuf.data() + sizeof(HVSNAP_DRAIN_HEADER),
                       sizeof(HVSNAP_RECORD), h->RecordCount, bin);
                totalRecords += h->RecordCount;
            }
            totalDropped = h->TotalDropped;
            if (h->MoreAvailable == 0 && h->RecordCount == 0) { break; }
        }
        {
            DWORD r2 = 0;
            DeviceIoControl(dev, HVSNAP_IOCTL_TRACE_STOP, nullptr, 0, nullptr, 0, &r2, nullptr);
        }
        fclose(bin);
        wprintf(L"[+] TRACE done: %llu records, %llu dropped -> %ls\n",
                totalRecords, totalDropped, binPath.c_str());
        wprintf(L"    Convert to CSV: hvctl trace-tocsv \"%ls\" trace.csv\n", binPath.c_str());
        rc = 0;
        goto cleanup;
    }

    // --- poll for the hit ---
    {
        HVSNAP_STATE st{};
        DWORD ret = 0;
        const DWORD deadline = GetTickCount() + opt.TimeoutSec * 1000;
        bool hit = false;
        while (GetTickCount() < deadline)
        {
            if (DeviceIoControl(dev, HVSNAP_IOCTL_QUERY, nullptr, 0, &st, sizeof(st), &ret, nullptr) &&
                st.Hit != 0)
            {
                hit = true;
                // Extended driver generations fill more of st; ret says how
                // much actually fit. Every level degrades gracefully against
                // an older driver (fields stay 0, provenance falls back).
                if (ret >= sizeof(st))
                {
                    measuredFsBase = st.HitFsBase;
                    measuredGsBase = st.HitGsBase;
                    haveMeasuredBases = true;
                    measuredCr0 = st.HitCr0;
                    measuredCr2 = st.HitCr2;
                    measuredCr3 = st.HitCr3;
                    measuredCr4 = st.HitCr4;
                    measuredEfer = st.HitEfer;
                    haveMeasuredControl = true;
                    measuredDr6 = st.HitDr6;
                    measuredDr7 = st.HitDr7;
                    measuredStar = st.HitStar;
                    measuredLStar = st.HitLStar;
                    measuredCStar = st.HitCStar;
                    measuredSfMask = st.HitSfMask;
                    measuredKernelGsBase = st.HitKernelGsBase;
                    measuredSysenterCs = st.HitSysenterCs;
                    measuredSysenterEsp = st.HitSysenterEsp;
                    measuredSysenterEip = st.HitSysenterEip;
                    measuredCpl = st.HitCpl;
                    measuredGPat = st.HitGPat;
                    measuredDbgCtl = st.HitDbgCtl;
                    measuredTscGuest = st.HitTscGuest;
                    measuredTscAux = st.HitTscAux;
                    measuredCr8 = st.HitCr8;
                    haveMeasuredExtended = true;
                }
                break;
            }
            Sleep(2);
        }
        if (!hit)
        {
            HVSNAP_STATE last{};
            DeviceIoControl(dev, HVSNAP_IOCTL_QUERY, nullptr, 0, &last, sizeof(last), &ret, nullptr);
            wprintf(L"[!] Timed out with no hit.");
            if (opt.HaveWhen)
            {
                wprintf(L" (predicate matched %llu time(s); RIP may not have been reached, "
                        L"or the condition never held.)", last.MatchCount);
            }
            wprintf(L" Cleaning up.\n");
            goto cleanup;
        }
        hitTid = static_cast<DWORD>(st.HitTid);
        wprintf(L"[+] HIT: tid=%llu parkedThreads=%llu matches=%llu\n",
                st.HitTid, st.ParkedCount, st.MatchCount);
    }

    // --- freeze: suspend EVERY thread in the target (consistent) ---
    {
        std::vector<DWORD> tids = EnumThreadIds(pid);
        size_t suspended = 0;
        for (DWORD tid : tids)
        {
            HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                                   FALSE, tid);
            if (th != nullptr)
            {
                if (SuspendThread(th) != (DWORD)-1) { ++suspended; }
                CloseHandle(th);
            }
        }
        wprintf(L"[+] FROZEN: suspended %zu/%zu threads.\n", suspended, tids.size());

        if (snapshotMode)
        {
            // Op1: dump the frozen target in Pinscan snapshot format.
            std::string outDir = Narrow(opt.OutDir);
            std::string prefix = Narrow(opt.Prefix);
            wprintf(L"[*] Writing snapshot (this may take a moment)...\n");
            bool ok = WriteSnapshot(proc, pid, hitTid, rip, outDir, prefix,
                                    measuredFsBase, measuredGsBase, haveMeasuredBases,
                                    measuredCr0, measuredCr2, measuredCr3,
                                    measuredCr4, measuredEfer, haveMeasuredControl,
                                    measuredDr6, measuredDr7, measuredStar, measuredLStar,
                                    measuredCStar, measuredSfMask, measuredKernelGsBase,
                                    measuredSysenterCs, measuredSysenterEsp, measuredSysenterEip,
                                    measuredCpl, measuredGPat, measuredDbgCtl,
                                    measuredTscGuest, measuredTscAux, measuredCr8,
                                    haveMeasuredExtended);
            wprintf(L"[%s] Snapshot %s.\n", ok ? L"+" : L"!", ok ? L"complete" : L"FAILED");
        }

        // Debugger hand-off: `debug` mode, or `snapshot --handoff` (dump THEN hand
        // off). Remove the NPT trap and restore the parked thread's RIP to the
        // target now (while suspended) so an attaching debugger shows the thread
        // sitting exactly at the target RIP -- not on the park stub.
        const bool doHandoff = debugMode || (snapshotMode && opt.Handoff);
        if (doHandoff)
        {
            const unsigned long long stubVa = reinterpret_cast<unsigned long long>(parkStub);
            {
                DWORD ret = 0;
                DeviceIoControl(dev, HVSNAP_IOCTL_DISARM, nullptr, 0, nullptr, 0, &ret, nullptr);
                armed = false;
            }
            for (DWORD tid : EnumThreadIds(pid))
            {
                HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
                if (th == nullptr) { continue; }
                alignas(16) CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_CONTROL;
                if (GetThreadContext(th, &ctx) && ctx.Rip == stubVa)
                {
                    ctx.Rip = rip;
                    SetThreadContext(th, &ctx);
                }
                CloseHandle(th);
            }
            wprintf(L"\n");
            wprintf(L"[+] DEBUG HANDOFF READY\n");
            wprintf(L"    PID       : %lu\n", pid);
            wprintf(L"    Frozen at : 0x%llx (thread %lu suspended exactly here)\n", rip, hitTid);
            wprintf(L"    NPT trap  : removed (target bytes are pristine)\n");
            if (snapshotMode) { wprintf(L"    Snapshot  : written before hand-off\n"); }
            wprintf(L"\n");
            wprintf(L"    Now attach your debugger to PID %lu (x64dbg: File > Attach;\n", pid);
            wprintf(L"    WinDbg: -p %lu). All threads are suspended, so after attaching\n", pid);
            wprintf(L"    resume them in the debugger (x64dbg Threads panel, or just Run/F9)\n");
            wprintf(L"    -- the target thread will continue from 0x%llx.\n\n", rip);
            if (opt.HoldSec >= 0)
            {
                wprintf(L"    Holding frozen for %d s (--hold), then resuming...\n", opt.HoldSec);
                Sleep(static_cast<DWORD>(opt.HoldSec) * 1000);
            }
            else
            {
                wprintf(L"    Press Enter here to have hvctl resume the threads and exit\n");
                wprintf(L"    (do this if you are NOT letting the debugger own execution)...\n");
                (void)getchar();
            }
        }
        else if (snapshotMode)
        {
            // Snapshot without hand-off: stay frozen if asked (--keep-frozen /
            // --hold N) so you can take another snapshot / inspect; else the thaw
            // below auto-resumes. The target stays parked-on-stub, trap armed.
            if (opt.KeepFrozen || opt.HoldSec >= 0)
            {
                if (opt.HoldSec >= 0)
                {
                    wprintf(L"[*] Target held FROZEN for %d s (--hold) after snapshot...\n",
                            opt.HoldSec);
                    Sleep(static_cast<DWORD>(opt.HoldSec) * 1000);
                }
                else
                {
                    wprintf(L"[*] Target held FROZEN after snapshot. Press Enter to thaw...\n");
                    (void)getchar();
                }
            }
        }
        else
        {
            wprintf(L"    Target is frozen at 0x%llx.", rip);
            if (opt.HoldSec >= 0)
            {
                wprintf(L" Holding %d s (--hold)...\n", opt.HoldSec);
                Sleep(static_cast<DWORD>(opt.HoldSec) * 1000);
            }
            else
            {
                wprintf(L" Inspect it, then press Enter to thaw...\n");
                (void)getchar();
            }
        }
    }

    // --- restore & resume ---
    {
        // 1) DISARM first (driver restores the NPT to the original large page).
        DWORD ret = 0;
        DeviceIoControl(dev, HVSNAP_IOCTL_DISARM, nullptr, 0, nullptr, 0, &ret, nullptr);
        armed = false;

        // 2) fix any thread parked on the stub (RIP -> original rip), resume all.
        std::vector<DWORD> tids = EnumThreadIds(pid);
        const unsigned long long stubVa = reinterpret_cast<unsigned long long>(parkStub);
        size_t fixed = 0;
        for (DWORD tid : tids)
        {
            HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                                   FALSE, tid);
            if (th == nullptr) { continue; }

            alignas(16) CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_CONTROL;
            if (GetThreadContext(th, &ctx) && ctx.Rip == stubVa)
            {
                ctx.Rip = rip;
                if (SetThreadContext(th, &ctx)) { ++fixed; }
            }
            ResumeThread(th);
            CloseHandle(th);
        }
        wprintf(L"[+] Thawed: fixed %zu parked thread(s), resumed threads.\n", fixed);
        if (opt.Cloak)
        {
            HVSNAP_STATE st{};
            DWORD qr = 0;
            if (DeviceIoControl(dev, HVSNAP_IOCTL_QUERY, nullptr, 0, &st, sizeof(st), &qr, nullptr))
            {
                wprintf(L"[+] TSC cloak: hid %llu cycles from the target so far "
                        L"(still active; run 'hvctl cloak-off' when done).\n", st.StolenTsc);
            }
        }
        rc = 0;
    }

    // --- optional termination after a clean thaw (--terminate-after) ---
    if (opt.TerminateAfter && proc != nullptr)
    {
        // The target is fully resumed at this point (trap disarmed, threads
        // fixed/resumed), so TerminateProcess is deliverable. Give it a brief
        // grace period, then kill and wait so nothing outlives the controller.
        if (TerminateProcess(proc, 0))
        {
            if (WaitForSingleObject(proc, 10000) == WAIT_OBJECT_0)
            {
                wprintf(L"[+] Terminated target (pid %lu) after snapshot (--terminate-after).\n", pid);
            }
            else
            {
                wprintf(L"[!] TerminateProcess issued but target did not exit within 10 s.\n");
            }
        }
        else
        {
            wprintf(L"[!] TerminateProcess failed (err %lu); target left running.\n", GetLastError());
        }
    }

cleanup:
    if (armed)
    {
        DWORD ret = 0;
        DeviceIoControl(dev, HVSNAP_IOCTL_DISARM, nullptr, 0, nullptr, 0, &ret, nullptr);
    }
    if (parkStub != nullptr && proc != nullptr) { VirtualFreeEx(proc, parkStub, 0, MEM_RELEASE); }
    // If we launched the target and never reached a clean thaw (rc != 0), don't
    // leave a suspended/half-initialized process behind -- kill it.
    if (launched && rc != 0 && proc != nullptr)
    {
        wprintf(L"[!] Terminating launched target (setup failed before freeze).\n");
        TerminateProcess(proc, 1);
    }
    if (hLaunchThread != nullptr) { CloseHandle(hLaunchThread); }
    if (proc != nullptr) { CloseHandle(proc); }
    if (dev != INVALID_HANDLE_VALUE) { CloseHandle(dev); }
    return rc;
}
