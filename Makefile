.PHONY: install install-dev test lint clean help

help:
	@echo "VRA - Vulnerability Research Automation"
	@echo "  install      Install VRA"
	@echo "  install-dev  Install VRA in development mode"
	@echo "  test         Run tests"
	@echo "  lint         Run linter"
	@echo "  clean        Remove build artifacts"

install:
	pip install .

install-dev:
	pip install -e ".[dev]"

test:
	python -m pytest tests/ -v --tb=short

lint:
	ruff check vra/ tests/
	ruff format --check vra/ tests/

format:
	ruff format vra/ tests/

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
