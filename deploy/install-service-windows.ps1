#Requires -RunAsAdministrator
# Robin Client Monitor - servicio Windows (NSSM + sc failure)
# Uso (PowerShell Admin):
#   cd "C:\Program Files\robin-client-monitor"
#   .\install-service-windows.ps1
# Env: ENROLLTOKEN / ENROLLSERVER / ENROLLTENANT / ENROLLNAME / ENROLLINSECURE=1
$ErrorActionPreference = "Stop"
$ServiceName = "robin-client-monitor"
$AppDir = if ($args.Count -ge 1 -and $args[0]) {
    $args[0].TrimEnd("\")
} else {
    $PSScriptRoot
}

$Bin = Join-Path $AppDir "robin-client-monitor.exe"
$nssmCandidates = @(
    (Join-Path $AppDir "nssm.exe"),
    (Join-Path $AppDir "nssm\nssm.exe"),
    (Join-Path $PSScriptRoot "nssm.exe"),
    (Join-Path $PSScriptRoot "nssm\nssm.exe")
)
$Nssm = $nssmCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

if (-not $Nssm) {
    Write-Error "no encuentro nssm.exe. Colocalo en $AppDir\nssm\ o junto a este script. Descarga: https://nssm.cc/download"
    exit 1
}
if (-not (Test-Path -LiteralPath $Bin)) {
    Write-Error "no existe $Bin. Copia robin-client-monitor.exe y config_client.json a $AppDir"
    exit 1
}

if ($env:ENROLLTOKEN) {
    Write-Host "Enrollment RF-CORE-01/02..."
    $enrollArgs = @("--enroll", $env:ENROLLTOKEN)
    if ($env:ENROLLSERVER) { $enrollArgs += @("--enroll-server", $env:ENROLLSERVER) }
    if ($env:ENROLLTENANT) { $enrollArgs += @("--enroll-tenant", $env:ENROLLTENANT) }
    if ($env:ENROLLNAME) { $enrollArgs += @("--enroll-name", $env:ENROLLNAME) }
    if ($env:ENROLLINSECURE -eq "1") { $enrollArgs += "--enroll-insecure" }
    Push-Location $AppDir
    try {
        & $Bin @enrollArgs
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            Write-Warning "enrollment fallo; se usara config_client.json."
        }
    } finally {
        Pop-Location
    }
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $existing) {
    & $Nssm install $ServiceName $Bin
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        Write-Error "nssm install fallo."
        exit 1
    }
} else {
    Write-Host "El servicio ya existe; se actualiza la configuracion."
}

& $Nssm set $ServiceName Application $Bin
& $Nssm set $ServiceName AppParameters "--max-retries -1 --retry-delay 2"
& $Nssm set $ServiceName AppDirectory $AppDir
& $Nssm set $ServiceName AppExit Default Restart
& $Nssm set $ServiceName AppRestartDelay 3000
& $Nssm set $ServiceName Start SERVICE_AUTO_START
& $Nssm set $ServiceName DisplayName "Robin Client Monitor"
& $Nssm start $ServiceName

sc.exe failure $ServiceName reset= 86400 actions= restart/3000/restart/10000/restart/30000 | Out-Null
sc.exe failureflag $ServiceName 1 | Out-Null

Write-Host ""
Write-Host "Listo. Estado:"
& $Nssm status $ServiceName
exit 0
