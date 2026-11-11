// probe.cpp - diagnose when a VA becomes mapped/executable in a launched target.
// Usage: probe.exe "<exe path>" 0x<va> [millisWindow]
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

static const char* Prot(DWORD p)
{
    switch (p & 0xFF)
    {
    case PAGE_NOACCESS: return "NOACCESS";
    case PAGE_READONLY: return "R";
    case PAGE_READWRITE: return "RW";
    case PAGE_EXECUTE: return "X";
    case PAGE_EXECUTE_READ: return "RX";
    case PAGE_EXECUTE_READWRITE: return "RWX";
    case PAGE_EXECUTE_WRITECOPY: return "RWXc";
    case PAGE_WRITECOPY: return "RWc";
    default: return "?";
    }
}
static const char* State(DWORD s)
{
    if (s == MEM_COMMIT) return "COMMIT";
    if (s == MEM_RESERVE) return "RESERVE";
    if (s == MEM_FREE) return "FREE";
    return "?";
}
static const char* Type(DWORD t)
{
    if (t == MEM_IMAGE) return "IMG";
    if (t == MEM_PRIVATE) return "PRV";
    if (t == MEM_MAPPED) return "MAP";
    return "-";
}

int wmain(int argc, wchar_t** argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 3) { wprintf(L"usage: probe \"<exe>\" 0x<va> [ms]\n"); return 1; }
    std::wstring exe = argv[1];
    unsigned long long va = _wcstoui64(argv[2], nullptr, 0);
    DWORD windowMs = (argc >= 4) ? (DWORD)_wcstoui64(argv[3], nullptr, 0) : 8000;

    std::wstring workdir = exe; size_t sl = workdir.find_last_of(L"\\/");
    if (sl != std::wstring::npos) workdir.resize(sl); else workdir.clear();
    std::wstring cmd = L"\"" + exe + L"\""; std::vector<wchar_t> cb(cmd.begin(), cmd.end()); cb.push_back(0);

    STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exe.c_str(), cb.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr,
                        workdir.empty() ? nullptr : workdir.c_str(), &si, &pi))
    { wprintf(L"CreateProcess failed %lu\n", GetLastError()); return 1; }

    HANDLE hp = pi.hProcess;
    // state at suspend:
    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T q = VirtualQueryEx(hp, (LPCVOID)va, &mbi, sizeof(mbi));
    printf("[t=-1 suspended] va=0x%llx query=%zu state=%s prot=%s type=%s base=0x%llx size=0x%llx\n",
           va, q, q?State(mbi.State):"-", q?Prot(mbi.Protect):"-", q?Type(mbi.Type):"-",
           q?(unsigned long long)mbi.BaseAddress:0ull, q?(unsigned long long)mbi.RegionSize:0ull);

    ResumeThread(pi.hThread);
    ULONGLONG t0 = GetTickCount64();
    // log transitions in state/prot for the VA
    std::string last = "(none)";
    int commitFirstMs = -1, execFirstMs = -1, transitions = 0;
    while (GetTickCount64() - t0 < windowMs)
    {
        MEMORY_BASIC_INFORMATION m{};
        SIZE_T r = VirtualQueryEx(hp, (LPCVOID)va, &m, sizeof(m));
        char cur[128];
        if (r == 0) { _snprintf_s(cur, sizeof(cur), _TRUNCATE, "queryfail(%lu)", GetLastError()); }
        else { _snprintf_s(cur, sizeof(cur), _TRUNCATE, "%s/%s/%s base=0x%llx size=0x%llx",
                           State(m.State), Prot(m.Protect), Type(m.Type),
                           (unsigned long long)m.BaseAddress, (unsigned long long)m.RegionSize); }
        if (last != cur)
        {
            int ms = (int)(GetTickCount64() - t0);
            printf("[t=+%5dms] %s\n", ms, cur);
            if (r && m.State == MEM_COMMIT && commitFirstMs < 0) commitFirstMs = ms;
            if (r && (m.Protect & 0xF0) /*any execute bit*/ && execFirstMs < 0 &&
                ((m.Protect & 0xFF)==PAGE_EXECUTE || (m.Protect&0xFF)==PAGE_EXECUTE_READ ||
                 (m.Protect&0xFF)==PAGE_EXECUTE_READWRITE || (m.Protect&0xFF)==PAGE_EXECUTE_WRITECOPY))
                execFirstMs = ms;
            last = cur; transitions++;
        }
        if (GetProcessId(hp) == 0) break;
        Sleep(0); // yield, tight poll
    }
    printf("\nSUMMARY va=0x%llx committed@=%dms firstExecProt@=%dms transitions=%d\n",
           va, commitFirstMs, execFirstMs, transitions);

    TerminateProcess(hp, 0);
    CloseHandle(pi.hThread); CloseHandle(hp);
    return 0;
}
