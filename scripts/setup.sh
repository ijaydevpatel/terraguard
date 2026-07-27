#!/usr/bin/env bash
# Local setup for macOS and Linux. Run from the repository root: bash scripts/setup.sh
set -euo pipefail

step() { printf '\n=== %s ===\n' "$1"; }

step "Checking prerequisites"
for tool in python3 git; do command -v "$tool" >/dev/null || { echo "$tool not on PATH"; exit 1; }; done
python3 --version; git --version
command -v terraform >/dev/null && terraform version | head -1 || echo "terraform not found (needed for the AWS steps only)"
command -v aws >/dev/null && aws --version || echo "aws cli not found (needed for the AWS steps only)"

step "Creating virtual environment"
[ -d .venv ] || python3 -m venv .venv
PY=.venv/bin/python

step "Installing dependencies"
$PY -m pip install --upgrade pip --quiet
$PY -m pip install -r requirements-dev.txt --quiet
$PY -m pip install -e . --quiet

step "Installing pre-commit hooks"
$PY -m pre_commit install

step "Verifying the state and plan file guard"
echo '{"version":4}' > terraform.tfstate
if $PY scripts/check_no_state_files.py terraform.tfstate; then
  rm -f terraform.tfstate; echo "Guard did NOT block a .tfstate file - investigate."; exit 1
else
  rm -f terraform.tfstate; echo "Guard works: the commit would have been refused."
fi

step "Running the test suite"
$PY -m pytest -q

step "Running the offline pipeline (no AWS credentials needed)"
$PY -m terraguard.cli collect --plan-json tests/fixtures/plan_sg_drift.json --output evidence/

echo; echo "Local setup complete."
