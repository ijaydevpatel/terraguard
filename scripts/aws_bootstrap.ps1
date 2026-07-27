<#
  Deploys the encrypted state backend, the cost guardrails and the secure baseline, in order.
  Run from the repository root AFTER `aws configure --profile terraguard`:
      powershell -ExecutionPolicy Bypass -File scripts\aws_bootstrap.ps1

  Safe to re-run: Terraform is idempotent.
#>

$ErrorActionPreference = "Stop"
$env:AWS_PROFILE = "terraguard"

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

Step "Confirming identity and region"
aws sts get-caller-identity
if (-not (Test-Path "terraform\bootstrap\terraform.tfvars")) {
    throw "terraform\bootstrap\terraform.tfvars is missing. Copy example.tfvars, set a globally unique bucket name and your alert email."
}

Step "Bootstrap: state bucket, lock table, budget alarms"
Push-Location terraform\bootstrap
terraform init -input=false
terraform apply -input=false -auto-approve
$bucket = (terraform output -raw state_bucket)
$region = (terraform output -raw -json 2>$null; "ap-southeast-2")
Write-Host "State bucket: $bucket" -ForegroundColor Green
terraform output -raw backend_block | Set-Content -Path "..\..\generated_backend.tf.txt"
Pop-Location

Step "Backend block written to generated_backend.tf.txt"
Write-Host "Paste its contents over terraform\baseline\backend.tf, then press Enter to continue." -ForegroundColor Yellow
Read-Host | Out-Null

Step "Baseline: security group, buckets, IAM, CloudTrail"
Push-Location terraform\baseline
terraform init -input=false
terraform apply -input=false -auto-approve
terraform output
Pop-Location

Step "Confirming a clean plan with zero drift"
Push-Location terraform\baseline
terraform plan -refresh-only -input=false -detailed-exitcode
$code = $LASTEXITCODE
Pop-Location
if ($code -eq 0) { Write-Host "Zero drift. Baseline is the reference state - Phase 5 can start." -ForegroundColor Green }
elseif ($code -eq 2) { Write-Host "Drift or changes detected on a fresh apply. Investigate before recording any scenario." -ForegroundColor Yellow }
else { throw "terraform plan failed." }

Step "Collecting the first evidence bundle"
Push-Location ..\..
Pop-Location
& .\.venv\Scripts\python.exe -m terraguard.cli collect --terraform-dir terraform\baseline --output evidence\ --scenario-id BASELINE-000
Write-Host "`nRemember: terraform destroy in terraform\baseline at the end of each session." -ForegroundColor Yellow
