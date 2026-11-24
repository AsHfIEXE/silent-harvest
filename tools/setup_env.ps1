# setup_env.ps1 -- create/refresh the operator venv with all requirements.
# Handles PATH-without-pip AND pip-less (uv-created) venvs.
#
#   powershell -ExecutionPolicy Bypass -File tools\setup_env.ps1
#
param(
    [string]$Python = "python"   # interpreter used to CREATE the venv
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$venv = Join-Path $root ".venv"
$vpip = Join-Path $venv "Scripts\python.exe"

if (Test-Path $vpip) {
    Write-Host "[ok] venv exists: $venv" -ForegroundColor Green
} else {
    Write-Host "[*] creating venv with '$Python'..." -ForegroundColor Cyan
    & $Python -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw "venv creation failed (is python installed?)" }
    Write-Host "[ok] venv created" -ForegroundColor Green
}

$req = Join-Path $root "requirements.txt"
$installed = $false

# native calls write to stderr on mere probes -- don't let Stop-EAP kill us
$ErrorActionPreference = "Continue"

# install path 1: uv (fast, works with pip-less venvs)
$uv = Get-Command uv -ErrorAction SilentlyContinue
if ($uv) {
    Write-Host "[*] installing requirements via uv..." -ForegroundColor Cyan
    & $uv.Source pip install --python $vpip -r $req 2>$null
    if ($LASTEXITCODE -eq 0) { $installed = $true }
}

# install path 2: pip (ensurepip first if the venv has no pip)
if (-not $installed) {
    Write-Host "[*] bootstrapping pip into the venv..." -ForegroundColor Cyan
    & $vpip -m ensurepip --upgrade 2>$null
    Write-Host "[*] installing requirements via pip..." -ForegroundColor Cyan
    & $vpip -m pip install -r $req 2>$null
    if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
}
$ErrorActionPreference = "Stop"

& $vpip -c "import cryptography; print('[ok] cryptography', cryptography.__version__)"
$imp = (& $vpip -c "import impacket; print('yes')") 2>$null
if ("$imp" -eq "yes") { Write-Host "[ok] impacket present (full offline chain enabled)" }

Write-Host ""
Write-Host "ready. use the venv interpreter for everything:" -ForegroundColor Yellow
Write-Host "  $vpip server\collector.py --port 8443 ..."
Write-Host "  $vpip server\c2ctl.py hosts"
Write-Host "  $vpip server\parse_loot.py"
Write-Host "  $vpip server\offline_unlock.py --bundle <dir>"
