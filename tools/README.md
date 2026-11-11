# hvsnap — load / unload tooling

Scripts to test-sign, load, and unload `hvsnap.sys`. **All three must be run from an
elevated (Administrator) PowerShell.**

## One-time host prep (before any of this works)
The custom AMD-V hypervisor runs on bare metal, so the Microsoft hypervisor must be gone,
and unsigned/test-signed kernel code must be allowed.

1. **Disable** Memory Integrity (Core Isolation), VBS, Hyper-V, and Secure Boot (the last in UEFI).
   - `bcdedit /set hypervisorlaunchtype off`
   - Turn off "Memory integrity" in Windows Security → Device security → Core isolation.
   - Disable Secure Boot in UEFI.
2. **Reboot**, then confirm the MS hypervisor is gone:
   ```powershell
   (Get-CimInstance Win32_ComputerSystem).HypervisorPresent   # must be False
   ```
3. **Enable test-signing**, then reboot again:
   ```powershell
   bcdedit /set testsigning on
   ```
   (A "Test Mode" watermark on the desktop is expected and harmless.)

> Note: Windows Update has previously re-enabled VBS/HVCI on this box. Re-check step 2
> after any update.

## Build (no admin needed)
Run from the `hvsnap` repo root:
```powershell
& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe" `
  hvsnap.sln /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off
```
`/p:SignMode=Off` skips the WDK auto-test-sign step (which fails without admin); we sign explicitly below.

## Sign → Load → Unload (elevated)
```powershell
cd tools   # from the hvsnap repo root
.\sign-hvsnap.ps1      # create+trust a test cert (idempotent), sign hvsnap.sys
.\load-hvsnap.ps1      # preflight checks, register kernel service, start it
# ... observe [hvsnap] output ...
.\unload-hvsnap.ps1    # stop (devirtualizes all CPUs) + delete the service
```

## Seeing `[hvsnap]` output
The driver uses `DbgPrint`-style logging (prefix `[hvsnap] `). `load-hvsnap.ps1` opens the
Debug Print Filter so the lines aren't dropped. View them with **DebugView**
(Sysinternals; run elevated, enable *Capture → Capture Kernel* and *Capture Events*) or an
attached kernel debugger (WinDbg).

## Phase-1 success criteria
- `load-hvsnap.ps1` returns and `sc query hvsnap` shows `RUNNING`.
- No BSOD; the machine stays responsive (every logical CPU is now virtualized).
- `unload-hvsnap.ps1` stops cleanly (devirtualize path runs, no crash).
- Re-running load/unload several times is stable.

If `sc start` fails: signature not trusted (re-run `sign-hvsnap.ps1`), test-signing not on,
or VBS still active. Check the **System** event log and DebugView.
