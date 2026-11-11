<#
  sign-hvsnap.ps1  --  create a self-signed test cert, trust it machine-wide,
                        and test-sign hvsnap.sys.

  RUN ELEVATED (admin). Safe to re-run: the cert is reused if it already exists.
  This only signs the binary. The kernel will accept the signature at load time
  ONLY when the machine is booted with test-signing on (bcdedit /set testsigning on)
  AND VBS/HVCI is off. See README.md.
#>
$ErrorActionPreference = 'Stop'

$Sys       = Join-Path $PSScriptRoot '..\x64\Release\hvsnap.sys'
$CertName  = 'hvsnap Test Cert'
$Subject   = "CN=$CertName"

# --- admin check ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
              [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run this script from an ELEVATED PowerShell (needs LocalMachine cert store + signing)." }
if (-not (Test-Path $Sys)) { throw "Driver not found: $Sys  (build it first with /p:SignMode=Off)" }

# --- locate newest x64 signtool ---
$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter signtool.exe -ErrorAction Stop |
            Where-Object { $_.FullName -like '*\x64\*' } |
            Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
Write-Host "signtool : $signtool"

# --- reuse or create the code-signing cert in LocalMachine\My ---
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq $Subject } | Select-Object -First 1
if (-not $cert) {
    # TextExtension 2.5.29.37 = Enhanced Key Usage; 1.3.6.1.5.5.7.3.3 = Code Signing
    $cert = New-SelfSignedCertificate -Type Custom -Subject $Subject `
                -KeyUsage DigitalSignature -KeySpec Signature -KeyExportPolicy Exportable `
                -CertStoreLocation Cert:\LocalMachine\My `
                -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3') `
                -NotAfter (Get-Date).AddYears(5)
    Write-Host "Created cert  : $($cert.Thumbprint)"
} else {
    Write-Host "Reusing cert  : $($cert.Thumbprint)"
}

# --- trust it: public cert -> LocalMachine Root + TrustedPublisher ---
$cer = Join-Path $env:TEMP 'hvsnap_test.cer'
Export-Certificate -Cert $cert -FilePath $cer -Force | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root           | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
Remove-Item $cer -Force
Write-Host "Trusted cert into LocalMachine\Root and \TrustedPublisher."

# --- sign (test signing: no timestamp required). /sm = use machine store ---
& $signtool sign /v /sm /s My /n $CertName /fd sha256 $Sys
if ($LASTEXITCODE -ne 0) { throw "signtool sign failed ($LASTEXITCODE)" }

Write-Host "`n--- signature check (authenticode chain) ---"
& $signtool verify /v /pa $Sys
Write-Host "`nNOTE: 'signtool verify /kp' (production kernel policy) will FAIL by design for a"
Write-Host "self-signed test cert. The real check is loading it with test-signing ON (load-hvsnap.ps1)."
