export UV_CACHE_DIR := $(CURDIR)/.uv-cache

.PHONY: setup check demo

setup:
	uv sync --locked --extra models --index-url https://pypi.org/simple

check:
	.venv/bin/ruff check .
	.venv/bin/ruff format --check .
	.venv/bin/mypy src
	.venv/bin/pytest

demo:
	mkdir -p reports
	.venv/bin/mail-triage triage fixtures/synthetic-phish.eml --out reports/demo-$$(date -u +%Y%m%dT%H%M%SZ)
