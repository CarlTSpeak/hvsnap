<#
  unload-hvsnap.ps1  --  stop + remove the hvsnap kernel service.
  Stopping triggers the driver's unload routine, which devirtualizes every CPU
  (via the VMMCALL bridge) before the driver image is freed.
  RUN ELEVATED.
#>
$ErrorActionPreference = 'Continue'
$SvcName = 'hvsnap'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
              [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run elevated." }

sc.exe stop   $SvcName
sc.exe delete $SvcName
Write-Host "hvsnap stopped + deleted. (If 'stop' said not running, it was already unloaded.)"
