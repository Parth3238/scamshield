# Apply pending migrations. Run from the backend folder:
#   powershell -ExecutionPolicy Bypass -File scripts\migrate.ps1
# New migration: .venv\Scripts\python.exe -m alembic revision --autogenerate -m "what changed"
$ErrorActionPreference = "Stop"
$Backend = Split-Path -Parent $PSScriptRoot
$VenvPython = Join-Path $Backend ".venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "ERROR: .venv not found. Run scripts\setup_dev.ps1 first."
    exit 1
}

Push-Location $Backend
try {
    & $VenvPython -m alembic upgrade head @args
} finally {
    Pop-Location
}
