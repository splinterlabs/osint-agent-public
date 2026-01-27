# OSINT Agent Makefile
# Common development and maintenance tasks

.PHONY: help install install-dev install-mcp test test-cov lint format typecheck clean clean-cache clean-all setup verify backup

# Default target
help:
	@echo "OSINT Agent - Available Commands"
	@echo ""
	@echo "Installation:"
	@echo "  make install       Install the package"
	@echo "  make install-dev   Install with development dependencies"
	@echo "  make install-mcp   Install MCP server"
	@echo "  make setup         Full setup (install + init databases)"
	@echo ""
	@echo "Development:"
	@echo "  make test          Run tests"
	@echo "  make test-cov      Run tests with coverage report"
	@echo "  make lint          Run linter (ruff)"
	@echo "  make format        Format code (ruff)"
	@echo "  make typecheck     Run type checker (mypy)"
	@echo "  make check         Run all checks (lint + typecheck + test)"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean         Remove build artifacts"
	@echo "  make clean-cache   Clear cached threat data"
	@echo "  make clean-all     Remove all generated files"
	@echo "  make backup        Backup databases and config"
	@echo "  make verify        Verify installation"
	@echo ""
	@echo "CLI shortcuts:"
	@echo "  make lookup CVE=CVE-2024-3400   Look up a CVE"
	@echo "  make intel                       Get threat intel summary"

# =============================================================================
# Installation
# =============================================================================

install:
	uv pip install -e .

install-dev:
	uv pip install -e ".[dev]"

install-mcp:
	cd mcp-server && uv sync

setup: install init-dirs init-db
	@echo "Setup complete! Run 'make verify' to check installation."

init-dirs:
	@mkdir -p data/cache data/context data/logs
	@mkdir -p .claude/data/cache .claude/data/logs
	@echo "Created data directories"

init-db:
	@python3 -c "\
import sqlite3; \
conn = sqlite3.connect('data/iocs.db'); \
conn.execute('CREATE TABLE IF NOT EXISTS iocs (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, value TEXT NOT NULL, source TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, hit_count INTEGER DEFAULT 1, UNIQUE(type, value))'); \
conn.execute('CREATE INDEX IF NOT EXISTS idx_type ON iocs(type)'); \
conn.execute('CREATE INDEX IF NOT EXISTS idx_value ON iocs(value)'); \
conn.close(); \
conn = sqlite3.connect('data/rate_limits.db'); \
conn.execute('CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, timestamp TEXT NOT NULL)'); \
conn.execute('CREATE INDEX IF NOT EXISTS idx_domain ON requests(domain)'); \
conn.close(); \
print('Initialized databases')"

# =============================================================================
# Development
# =============================================================================

test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=src/osint_agent --cov-report=term-missing --cov-report=html

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

typecheck:
	mypy src/ --ignore-missing-imports

check: lint typecheck test
	@echo "All checks passed!"

# =============================================================================
# Maintenance
# =============================================================================

clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	rm -rf htmlcov/ .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleaned build artifacts"

clean-cache:
	rm -rf data/cache/*
	rm -rf .claude/data/cache/*
	@echo "Cleared cached data"

clean-all: clean clean-cache
	rm -f data/iocs.db data/rate_limits.db
	rm -f data/logs/*.jsonl .claude/data/logs/*.jsonl
	@echo "Cleaned all generated files"

backup:
	@mkdir -p backups
	@TIMESTAMP=$$(date +%Y%m%d_%H%M%S); \
	tar -czf backups/osint-agent-backup-$$TIMESTAMP.tar.gz \
		data/iocs.db \
		data/rate_limits.db \
		config/*.json \
		2>/dev/null || true; \
	echo "Backup created: backups/osint-agent-backup-$$TIMESTAMP.tar.gz"

verify:
	@echo "Verifying installation..."
	@python3 -c "import osint_agent; print('  ✓ osint_agent module')" || echo "  ✗ osint_agent module"
	@python3 -m osint_agent.cli --help > /dev/null 2>&1 && echo "  ✓ CLI working" || echo "  ✗ CLI not working"
	@test -f data/iocs.db && echo "  ✓ IOC database" || echo "  ✗ IOC database missing"
	@test -f config/watchlist.json && echo "  ✓ Watchlist config" || echo "  ✗ Watchlist config missing"
	@test -d .claude/commands && echo "  ✓ Claude commands" || echo "  ✗ Claude commands missing"
	@echo "Verification complete"

# =============================================================================
# CLI Shortcuts
# =============================================================================

lookup:
ifndef CVE
	@echo "Usage: make lookup CVE=CVE-2024-3400"
else
	.venv/bin/python -m osint_agent.cli lookup $(CVE) --format text
endif

intel:
	.venv/bin/python -m osint_agent.cli intel

# =============================================================================
# Docker (optional)
# =============================================================================

docker-build:
	docker build -t osint-agent:latest .

docker-run:
	docker run -it --rm -v $(PWD)/data:/app/data osint-agent:latest
