.PHONY: install test lint fmt guard secrets check demo clean

install:
	pip install -r requirements-dev.txt && pip install -e . && pre-commit install

test:
	pytest -q

lint:
	ruff check terraguard scripts tests && black --check terraguard scripts tests

fmt:
	black terraguard scripts tests && ruff check --fix terraguard scripts tests

guard:
	git ls-files | xargs python scripts/check_no_state_files.py

secrets:
	# gitleaks runs in CI but not in requirements-dev; the pre-commit hook is the local route.
	pre-commit run gitleaks --all-files

check: guard test lint secrets
	# everything CI runs, in the same order

demo:
	terraguard collect --plan-json tests/fixtures/plan_sg_drift.json --output evidence/

clean:
	rm -rf evidence .pytest_cache .ruff_cache **/__pycache__
