# -------------------------------------------------
# Setup: create venv, install the package editable
# Run from Project/ root:  .\setup_project.ps1
# -------------------------------------------------
$ErrorActionPreference = "Stop"

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# 1. Create virtual environment if it doesn't exist
$venvDir = Join-Path $projectDir ".venv"
if (-not (Test-Path $venvDir)) {
    Write-Host "Creating virtual environment in .venv ..."
    python -m venv $venvDir
}

# 2. Activate the virtual environment
$activateScript = Join-Path $venvDir "Scripts\Activate.ps1"
& $activateScript

# 3. Install the package in editable mode (+ all dependencies)
python -m pip install -e $projectDir

Write-Host ""
Write-Host "========================================="
Write-Host "  Setup complete!"
Write-Host "========================================="
Write-Host ""
Write-Host "  Scan a directory:"
Write-Host "    python -m secret_scanner.core.scanner ."
Write-Host "    python -m secret_scanner.core.scanner . --json"
Write-Host ""
Write-Host "  Start the API server:"
Write-Host "    python -m uvicorn secret_scanner.api:app --host 127.0.0.1 --port 8000"
Write-Host ""
