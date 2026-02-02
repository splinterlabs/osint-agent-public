# ============================================================================
# OSINT Agent - Development Workflow
# ============================================================================
# All commands are designed to work for both humans and AI agents.
# Run 'make help' to see all available commands.

.PHONY: help
help:  ## Show this help message
	@echo "OSINT Agent - Available Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ============================================================================
# SETUP COMMANDS (Run once per environment)
# ============================================================================

.PHONY: init
init: check-deps setup-venv setup-config init-dirs init-db validate  ## Full initialization (run this first!)
	@echo "✅ Project initialized! Run 'make status' to check everything."

.PHONY: check-deps
check-deps:  ## Verify system dependencies
	@echo "🔍 Checking system dependencies..."
	@command -v python3 >/dev/null 2>&1 || { echo "❌ Python 3 not found. Install it first."; exit 1; }
	@python3 -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)" || { echo "❌ Python 3.11+ required. You have: $$(python3 --version)"; exit 1; }
	@command -v uv >/dev/null 2>&1 || { echo "⚠️  uv not found (install: https://docs.astral.sh/uv/)"; }
	@echo "✅ System dependencies OK"

.PHONY: setup-venv
setup-venv:  ## Create virtual environment and install dependencies
	@echo "📦 Setting up Python virtual environment..."
	@test -d .venv || python3 -m venv .venv
	@.venv/bin/pip install --upgrade pip uv
	@.venv/bin/uv pip install -e ".[dev]"
	@echo "✅ Virtual environment ready"

.PHONY: setup-config
setup-config:  ## Create config files from examples
	@echo "⚙️  Setting up configuration..."
	@test -f config/watchlist.json || cp config/watchlist.example.json config/watchlist.json && echo "✅ Created config/watchlist.json (customize as needed)"
	@test -f .env || (test -f .env.example && cp .env.example .env && echo "✅ Created .env (add your API keys!)") || echo "⚠️  No .env.example found"

.PHONY: init-dirs
init-dirs:  ## Create required directories
	@echo "📁 Creating data directories..."
	@mkdir -p data/cache data/context data/logs data/logs/investigations data/campaigns
	@mkdir -p .claude/data/cache .claude/data/logs
	@mkdir -p logs reports backups
	@mkdir -p .claude/prompts
	@echo "✅ Directories created"

.PHONY: init-db
init-db:  ## Initialize databases
	@echo "🗄️  Initializing databases..."
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
print('✅ Databases initialized')"

.PHONY: setup-mcp
setup-mcp:  ## Install MCP server (optional)
	@echo "📡 Setting up MCP server..."
	@cd mcp-server && uv sync
	@echo "✅ MCP server ready"

# ============================================================================
# VALIDATION COMMANDS
# ============================================================================

.PHONY: validate
validate:  ## Full validation of installation
	@echo "🔍 Validating installation..."
	@mkdir -p logs
	@echo "=== System Dependencies ===" | tee logs/validation.log
	@make check-deps 2>&1 | tee -a logs/validation.log
	@echo "" | tee -a logs/validation.log
	@echo "=== Virtual Environment ===" | tee -a logs/validation.log
	@test -d .venv && echo "  ✅ Virtual environment exists" | tee -a logs/validation.log || echo "  ❌ Virtual environment missing (run: make setup-venv)" | tee -a logs/validation.log
	@test -d .venv && .venv/bin/python -c "import osint_agent; print('  ✅ osint_agent module installed')" 2>&1 | tee -a logs/validation.log || echo "  ❌ osint_agent not installed" | tee -a logs/validation.log
	@echo "" | tee -a logs/validation.log
	@echo "=== Configuration ===" | tee -a logs/validation.log
	@test -f config/watchlist.json && echo "  ✅ config/watchlist.json exists" | tee -a logs/validation.log || echo "  ⚠️  config/watchlist.json missing (optional)" | tee -a logs/validation.log
	@test -f .env && echo "  ✅ .env exists" | tee -a logs/validation.log || echo "  ⚠️  .env missing (API keys optional)" | tee -a logs/validation.log
	@echo "" | tee -a logs/validation.log
	@echo "=== Databases ===" | tee -a logs/validation.log
	@test -f data/iocs.db && echo "  ✅ IOC database initialized" | tee -a logs/validation.log || echo "  ❌ IOC database missing (run: make init-db)" | tee -a logs/validation.log
	@test -f data/rate_limits.db && echo "  ✅ Rate limit database initialized" | tee -a logs/validation.log || echo "  ❌ Rate limit database missing (run: make init-db)" | tee -a logs/validation.log
	@echo "" | tee -a logs/validation.log
	@echo "=== Claude Code Integration ===" | tee -a logs/validation.log
	@test -d .claude/commands && echo "  ✅ Claude commands directory exists" | tee -a logs/validation.log || echo "  ⚠️  Claude commands missing" | tee -a logs/validation.log
	@echo "" | tee -a logs/validation.log
	@echo "Full validation log saved to: logs/validation.log"

.PHONY: status
status:  ## Quick status summary
	@echo "📊 OSINT Agent Status:"
	@echo ""
	@echo "Dependencies:"
	@command -v python3 >/dev/null 2>&1 && echo "  ✅ Python: $$(python3 --version)" || echo "  ❌ Python: not found"
	@command -v uv >/dev/null 2>&1 && echo "  ✅ uv: $$(uv --version)" || echo "  ⚠️  uv: not found"
	@echo ""
	@echo "Environment:"
	@test -d .venv && echo "  ✅ Virtual environment ready" || echo "  ❌ Virtual environment missing (run: make setup-venv)"
	@test -d .venv && .venv/bin/python -c "import osint_agent" 2>/dev/null && echo "  ✅ osint_agent installed" || echo "  ❌ osint_agent not installed"
	@echo ""
	@echo "Configuration:"
	@test -f .env && echo "  ✅ .env exists" || echo "  ⚠️  .env missing (API keys optional)"
	@test -f config/watchlist.json && echo "  ✅ watchlist.json configured" || echo "  ⚠️  watchlist.json missing"
	@echo ""
	@echo "Databases:"
	@test -f data/iocs.db && echo "  ✅ IOC database ready" || echo "  ❌ IOC database missing (run: make init-db)"
	@test -f data/rate_limits.db && echo "  ✅ Rate limit database ready" || echo "  ❌ Rate limit database missing (run: make init-db)"
	@echo ""
	@test -d .venv && test -f data/iocs.db && echo "🚀 Ready! Use slash commands in Claude Code or run: python -m osint_agent.cli --help" || echo "⚙️  Setup needed. Run: make init"

# ============================================================================
# DEVELOPMENT COMMANDS
# ============================================================================

.PHONY: install
install:  ## Install package in development mode
	@.venv/bin/uv pip install -e .

.PHONY: install-dev
install-dev:  ## Install with development dependencies
	@.venv/bin/uv pip install -e ".[dev]"

.PHONY: test
test:  ## Run tests
	@.venv/bin/pytest tests/ -v

.PHONY: test-cov
test-cov:  ## Run tests with coverage report
	@.venv/bin/pytest tests/ -v --cov=src/osint_agent --cov-report=term-missing --cov-report=html

.PHONY: lint
lint:  ## Run linter (ruff)
	@.venv/bin/ruff check src/ tests/

.PHONY: format
format:  ## Format code (ruff)
	@.venv/bin/ruff format src/ tests/
	@.venv/bin/ruff check --fix src/ tests/

.PHONY: typecheck
typecheck:  ## Run type checker (mypy)
	@.venv/bin/mypy src/ --ignore-missing-imports

.PHONY: check
check: lint typecheck test  ## Run all quality checks (pre-commit)
	@echo "✅ All checks passed!"

# ============================================================================
# MAINTENANCE COMMANDS
# ============================================================================

.PHONY: update
update:  ## Update dependencies
	@echo "⬆️  Updating dependencies..."
	@.venv/bin/uv pip install --upgrade -e ".[dev]"
	@test -d mcp-server && cd mcp-server && uv sync --upgrade || true
	@echo "✅ Dependencies updated"

.PHONY: clean
clean:  ## Clean build artifacts and old logs
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf build/ dist/ *.egg-info src/*.egg-info
	@rm -rf .pytest_cache .mypy_cache .ruff_cache
	@rm -rf htmlcov/ .coverage
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find logs -name "*.log" -mtime +7 -delete 2>/dev/null || true
	@echo "✅ Clean complete"

.PHONY: clean-cache
clean-cache:  ## Clear cached threat data
	@echo "🧹 Clearing cached data..."
	@rm -rf data/cache/*
	@rm -rf .claude/data/cache/*
	@echo "✅ Cache cleared"

.PHONY: clean-all
clean-all: clean clean-cache  ## Deep clean (removes databases and logs)
	@echo "🧹 Deep cleaning..."
	@rm -f data/iocs.db data/rate_limits.db
	@rm -f data/logs/*.jsonl .claude/data/logs/*.jsonl
	@echo "✅ Deep clean complete. Run 'make init' to reinitialize."

.PHONY: backup
backup:  ## Backup databases and config
	@mkdir -p backups
	@TIMESTAMP=$$(date +%Y%m%d_%H%M%S); \
	tar -czf backups/osint-agent-backup-$$TIMESTAMP.tar.gz \
		data/iocs.db \
		data/rate_limits.db \
		data/campaigns/*.json \
		config/*.json \
		2>/dev/null || true; \
	echo "💾 Backup created: backups/osint-agent-backup-$$TIMESTAMP.tar.gz"

# ============================================================================
# CLI SHORTCUTS
# ============================================================================

.PHONY: lookup
lookup:  ## Look up a CVE (usage: make lookup CVE=CVE-2024-3400)
ifndef CVE
	@echo "Usage: make lookup CVE=CVE-2024-3400"
else
	@.venv/bin/python -m osint_agent.cli lookup $(CVE) --format text
endif

.PHONY: intel
intel:  ## Get threat intel summary
	@.venv/bin/python -m osint_agent.cli intel

# ============================================================================
# DOCKER (OPTIONAL)
# ============================================================================

.PHONY: docker-build
docker-build:  ## Build Docker image
	@docker build -t osint-agent:latest .

.PHONY: docker-run
docker-run:  ## Run in Docker container
	@docker run -it --rm -v $(PWD)/data:/app/data osint-agent:latest
