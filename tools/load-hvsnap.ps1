<#
  load-hvsnap.ps1  --  register hvsnap.sys as a kernel service and start it.

  RUN ELEVATED, AFTER:
    1. VBS/HVCI/Hyper-V + Secure Boot disabled and rebooted
       (verify: (gcim Win32_ComputerSystem).HypervisorPresent  ->  False)
    2. bcdedit /set testsigning on   (then reboot)
    3. sign-hvsnap.ps1 has signed the .sys

  [hvsnap] DbgPrint output is visible in DebugView (Capture > Kernel + Events)
  or a kernel debugger. This script also opens the Debug Print Filter so the
  prints are not silently dropped.
#>
$ErrorActionPreference = 'Stop'

$Sys     = Join-Path $PSScriptRoot '..\x64\Release\hvsnap.sys'
$SvcName = 'hvsnap'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
              [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run elevated." }
if (-not (Test-Path $Sys)) { throw "Driver not found: $Sys" }

# --- preflight: the custom SVM hypervisor CANNOT run under the MS hypervisor ---
if ((Get-CimInstance Win32_ComputerSystem).HypervisorPresent) {
    Write-Warning "HypervisorPresent = True -> VBS/Hyper-V still active. hvsnap will fail to VMRUN."
    Write-Warning "Disable Memory Integrity/VBS/Hyper-V (+ Secure Boot) and reboot first. Aborting."
    return
}
$ts = (bcdedit | Select-String 'testsigning').Line
Write-Host "testsigning  : $ts"
if ($ts -notmatch 'Yes') { Write-Warning "test-signing does not look enabled; load will likely be blocked." }

# --- let DbgPrint through (IHVDRIVER component, all levels) ---
$dpf = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter'
New-Item -Path $dpf -Force | Out-Null
New-ItemProperty -Path $dpf -Name DEFAULT -PropertyType DWord -Value 0xFFFFFFFF -Force | Out-Null

# --- (re)create + start the kernel service ---
sc.exe stop   $SvcName   *> $null
sc.exe delete $SvcName   *> $null
sc.exe create $SvcName type= kernel start= demand binPath= "$Sys"
if ($LASTEXITCODE -ne 0) { throw "sc create failed ($LASTEXITCODE)" }

sc.exe start $SvcName
if ($LASTEXITCODE -ne 0) {
    Write-Warning "sc start failed ($LASTEXITCODE). Common causes: signature not trusted (run sign-hvsnap.ps1),"
    Write-Warning "test-signing off, or VBS still on. Check 'System' event log + DebugView."
    throw "start failed"
}
Write-Host "`nhvsnap started. Status:"
sc.exe query $SvcName
Write-Host "`nWatch [hvsnap] lines in DebugView (Capture Kernel). Unload with unload-hvsnap.ps1."
