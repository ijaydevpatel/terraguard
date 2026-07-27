.PHONY: install test lint fmt guard demo clean

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

demo:
	terraguard collect --plan-json tests/fixtures/plan_sg_drift.json --output evidence/

clean:
	rm -rf evidence .pytest_cache .ruff_cache **/__pycache__
