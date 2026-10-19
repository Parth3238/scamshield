# Start the dev server. Run from the backend folder:
#   powershell -ExecutionPolicy Bypass -File scripts\run_backend.ps1
$ErrorActionPreference = "Stop"
$Backend = Split-Path -Parent $PSScriptRoot
$VenvPython = Join-Path $Backend ".venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "ERROR: .venv not found. Run scripts\setup_dev.ps1 first."
    exit 1
}

if (-not $env:SECRET_KEY) {
    # Session-only key: generated fresh, never written to any file.
    # Logins/cookies from this session stop working when it ends.
    $bytes = New-Object byte[] 36
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $env:SECRET_KEY = [Convert]::ToBase64String($bytes)
    Write-Host "WARNING: SECRET_KEY was not set. Using a random key for this session only - logins will reset next time."
    Write-Host "To keep logins, set SECRET_KEY in your environment before running this script."
}

Push-Location $Backend
try {
    & $VenvPython -m uvicorn app.main:app --reload
} finally {
    Pop-Location
}
