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
Write-Host "  Start the web dashboard:"
Write-Host "    python -m secret_scanner"
Write-Host ""
Write-Host "  This will open http://127.0.0.1:8000 in your browser."
Write-Host ""
