<#
  One-shot local setup for Windows. Run from the repository root:
      powershell -ExecutionPolicy Bypass -File scripts\setup.ps1

  Creates the virtual environment, installs everything, installs the pre-commit hooks,
  runs the test suite, and proves the offline pipeline works without AWS credentials.
#>

$ErrorActionPreference = "Stop"

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

Step "Checking prerequisites"
foreach ($tool in @("python", "git")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool is not on PATH. Install it and re-run."
    }
}
python --version
git --version
if (Get-Command terraform -ErrorAction SilentlyContinue) { terraform version | Select-Object -First 1 }
else { Write-Host "terraform not found - needed before the AWS steps, not for the tests" -ForegroundColor Yellow }
if (Get-Command aws -ErrorAction SilentlyContinue) { aws --version }
else { Write-Host "aws cli not found - needed before the AWS steps" -ForegroundColor Yellow }

Step "Creating virtual environment"
if (-not (Test-Path ".venv")) { python -m venv .venv }
$py = ".\.venv\Scripts\python.exe"

Step "Installing dependencies"
& $py -m pip install --upgrade pip --quiet
& $py -m pip install -r requirements-dev.txt --quiet
& $py -m pip install -e . --quiet

Step "Installing pre-commit hooks"
& $py -m pre_commit install

Step "Verifying the state and plan file guard blocks a deliberate commit"
Set-Content -Path "terraform.tfstate" -Value '{"version":4}'
$blocked = $false
& $py scripts\check_no_state_files.py terraform.tfstate
if ($LASTEXITCODE -ne 0) { $blocked = $true }
Remove-Item "terraform.tfstate" -Force
if ($blocked) { Write-Host "Guard works: the commit would have been refused." -ForegroundColor Green }
else { throw "Guard did NOT block a .tfstate file. Investigate before committing anything." }

Step "Running the test suite"
& $py -m pytest -q

Step "Running the offline pipeline (no AWS credentials needed)"
& $py -m terraguard.cli collect --plan-json tests\fixtures\plan_sg_drift.json --output evidence\

Write-Host "`nLocal setup complete." -ForegroundColor Green
Write-Host "Next: scripts\aws_bootstrap.ps1 once the AWS CLI profile is configured." -ForegroundColor Green
