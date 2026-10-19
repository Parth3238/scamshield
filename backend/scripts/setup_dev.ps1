# First-time (or repair) setup. Run from the backend folder:
#   powershell -ExecutionPolicy Bypass -File scripts\setup_dev.ps1
# Uses the venv Python directly; the venv is never "activated".
$ErrorActionPreference = "Stop"
$Backend = Split-Path -Parent $PSScriptRoot
$VenvPython = Join-Path $Backend ".venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "No venv found, creating one..."
    $created = $false
    foreach ($cmd in @("python", "py")) {
        try {
            & $cmd -m venv (Join-Path $Backend ".venv") 2>$null
            if (Test-Path $VenvPython) { $created = $true; break }
        } catch { }
    }
    if (-not $created) {
        Write-Host "ERROR: no working system Python found."
        Write-Host "Install Python 3.12 from python.org with 'Add python.exe to PATH' ticked, then re-run this script."
        exit 1
    }
}

& $VenvPython -m pip install -r (Join-Path $Backend "requirements.txt") -r (Join-Path $Backend "requirements-dev.txt")
Push-Location $Backend
try {
    & $VenvPython -m alembic upgrade head
} finally {
    Pop-Location
}
Write-Host "Setup done."
