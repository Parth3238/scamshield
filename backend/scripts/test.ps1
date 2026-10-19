# Run the backend tests. Run from the backend folder:
#   powershell -ExecutionPolicy Bypass -File scripts\test.ps1
$ErrorActionPreference = "Stop"
$Backend = Split-Path -Parent $PSScriptRoot
$VenvPython = Join-Path $Backend ".venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "ERROR: .venv not found. Run scripts\setup_dev.ps1 first."
    exit 1
}

Push-Location $Backend
try {
    & $VenvPython -m pytest @args
} finally {
    Pop-Location
}
