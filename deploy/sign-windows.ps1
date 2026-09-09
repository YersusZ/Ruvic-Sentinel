#Requires -Version 5.1
<#
.SYNOPSIS
  Firma Authenticode (§16) de .exe / .msi / instalador Inno.

.DESCRIPTION
  Requiere un PFX (o certificado en el store) y signtool.exe (Windows SDK).
  No hay certificados en el repo: pasalos por CI (secreto).

.ENVIRONMENT
  AUTHENTICODE_PFX           ruta al .pfx
  AUTHENTICODE_PASSWORD      password del PFX
  AUTHENTICODE_TIMESTAMP_URL default http://timestamp.digicert.com
  AUTHENTICODE_CERT_SHA1     thumbprint en el store (alternativa a PFX)

.EXAMPLE
  .\deploy\sign-windows.ps1 dist\robin-client-monitor.exe dist\robin-client-monitor.msi
#>
param(
  [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)]
  [string[]]$Files
)

$ErrorActionPreference = "Stop"
$ts = $env:AUTHENTICODE_TIMESTAMP_URL
if (-not $ts) { $ts = "http://timestamp.digicert.com" }

$signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if (-not $signtool) {
  $candidates = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
    "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
  )
  $found = Get-Item $candidates -ErrorAction SilentlyContinue | Select-Object -Last 1
  if ($found) {
    $signtool = $found.FullName
  } else {
    Write-Error "signtool.exe no está en PATH. Instalá Windows SDK."
  }
} else {
  $signtool = $signtool.Source
}

$common = @("sign", "/fd", "SHA256", "/tr", $ts, "/td", "SHA256")
if ($env:AUTHENTICODE_PFX) {
  $common += @("/f", $env:AUTHENTICODE_PFX)
  if ($env:AUTHENTICODE_PASSWORD) {
    $common += @("/p", $env:AUTHENTICODE_PASSWORD)
  }
} elseif ($env:AUTHENTICODE_CERT_SHA1) {
  $common += @("/sha1", $env:AUTHENTICODE_CERT_SHA1)
} else {
  Write-Error "Definí AUTHENTICODE_PFX (+ AUTHENTICODE_PASSWORD) o AUTHENTICODE_CERT_SHA1"
}

foreach ($f in $Files) {
  if (-not (Test-Path -LiteralPath $f)) {
    Write-Error "No existe $f"
  }
  & $signtool @common $f
  if ($LASTEXITCODE -ne 0) {
    Write-Error "signtool falló en $f (exit $LASTEXITCODE)"
  }
  Write-Host "[sign] OK $f"
}
