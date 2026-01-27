# Changelog

## [Unreleased] - 2026-01-27

### Added

- **Investigation step logging** (`src/osint_agent/investigation_log.py`): Per-investigation JSONL log files that capture raw enrichment results while keeping console output compact:
  - `InvestigationLogger` class with `write_header()`, `log_step()`, `write_conclusion()`, `read_log()`
  - Log files saved to `data/logs/investigations/` with sanitized filenames
  - Three new MCP tools: `log_investigation_step`, `log_investigation_conclusion`, `get_investigation_log`
  - Integrated into `start_investigation` — log file created automatically
  - `/investigate` now prints compact one-liners during enrichment; raw data goes to JSONL
  - `/review` can read back investigation logs for raw data access

- **Transparent API response caching** (`src/osint_agent/cache.py`): Reduces redundant API requests across enrichment steps with configurable TTLs per service.

- **Per-investigation usage tracking** (`src/osint_agent/usage.py`): Tracks MCP tool calls and API requests per investigation:
  - `UsageTracker` class with thread-safe counters
  - `@track_tool` decorator for automatic tool call recording
  - `get_investigation_usage` MCP tool for statistics
  - Usage footnote displayed at the end of all slash commands

- **Parallel execution module** (`src/osint_agent/parallel.py`): Reusable `ThreadPoolExecutor`-based utilities for concurrent processing:
  - `parallel_map()` - execute function on items in parallel, returns results in input order
  - `parallel_filter_map()` - parallel map with None filtering, ideal for extract-and-filter workflows
  - `parallel_collect_sets()` - thread-safe set aggregation across parallel workers
  - `ParallelMetrics` dataclass for operation logging (tasks submitted/completed/failed, timing)
  - Configurable worker pools loaded from `config/settings.json`
  - Graceful error handling: failed tasks return None instead of crashing the batch

- **Parallelism configuration** (`config/settings.json`): Worker pool sizes for each operation type:
  - `ioc_lookup_workers`: 10
  - `campaign_correlation_workers`: 20
  - `feed_processing_workers`: 10
  - `vendor_search_workers`: 5
  - `max_concurrent_requests`: 50
  - `enabled` flag to disable parallelism globally

- **Comprehensive Claude Code permissions** (`.claude/settings.local.json`): Pre-authorized 100+ MCP tool permissions across 12 categories (CVE, IOC, OTX, Abuse.ch, Shodan, ATT&CK, campaigns, rules, context, FreshRSS, web fetch, WHOIS/RIR, Maigret)

- **Local web fetch tools** (`mcp-server/tools/web_fetch_tools.py`): Alternative to built-in WebFetch with realistic browser headers:
  - `local_web_fetch` - HTML/text content with automatic text extraction
  - `local_web_fetch_json` - JSON API responses
  - `local_web_fetch_raw` - Binary content with base64 encoding
  - Rotating User-Agent pool (Chrome, Firefox, Safari, Edge)

- **Structured investigation workflow** (`.claude/commands/investigate.md`): Multi-source indicator enrichment with context isolation, coverage tracking, and verdict synthesis

- **Independent review judge layer** (`.claude/commands/review.md`): 16-check structured review across false positive analysis, logical consistency, confidence calibration, coverage gaps, and analytical rigor

### Changed

- **Campaign correlation** (`src/osint_agent/correlation.py`): `correlate_campaign_iocs()` now uses `parallel_collect_sets()` for concurrent campaign lookups.

- **FreshRSS IOC extraction** (`mcp-server/tools/freshrss_tools.py`): `freshrss_extract_iocs()` now processes feed entries concurrently with `parallel_filter_map()`.

- **`/investigate` console output**: Enrichment steps now print compact one-liners (`[Source] status -- summary`) instead of verbose raw data. Full results are logged to JSONL.

- **`/investigate` report format**: Removed "Raw Details" section. Added footer linking to the investigation log file.

### Fixed

- **Abuse.ch API calls** (`898ae26`): Added `Auth-Key` header and corrected content types for URLhaus, MalwareBazaar, and ThreatFox.

## [0.1.0] - 2026-01-23

### Added

- **Core platform**: CLI, MCP server, Claude Code hooks and slash commands
- **CVE & vulnerability tools**: NVD lookups (`lookup_cve`, `get_critical_cves`), CISA KEV checks (`check_kev`, `search_kev_vendor`, `get_kev_stats`)
- **IOC extraction**: Extract IPs, domains, hashes, URLs, emails, CVEs from text; handles defanged IOCs
- **STIX 2.1 export**: Convert IOCs to STIX bundles with observables and indicators
- **AlienVault OTX integration**: IOC lookups, pulse search, pulse details, subscribed feeds
- **Abuse.ch integration**: URLhaus (URL/host lookup, recent URLs), MalwareBazaar (hash lookup, search, recent samples), ThreatFox (IOC lookup, search, recent IOCs)
- **Shodan integration**: Host lookups, search, DNS resolution, vulnerability details, exploit search
- **MITRE ATT&CK integration**: Technique/group/software lookups, tactic listing, technique search, behavior mapping
- **Campaign tracking**: Create/manage campaigns with IOCs, TTPs, CVEs, status tracking, correlation analysis
- **Detection rules**: YARA rule generation from hashes, Sigma rules for network/DNS/firewall logs
- **FreshRSS integration**: Feed listing, entry retrieval, unread management, IOC extraction from feeds, keyword search
- **Context management**: Five-tier investigation context (strategic, operational, tactical, technical, security)
- **Watchlist system**: Monitor vendors/products/keywords with session-start alerting
- **IOC database**: SQLite-backed local IOC storage with CLI query interface (`/iocs`)
- **Claude Code slash commands**: `/cve`, `/intel`, `/extract-iocs`, `/iocs`, `/watchlist`, `/investigate`, `/review`
- **Session start hook**: Automated threat briefing with critical CVEs, KEV additions, watchlist alerts, IOC stats
- **Health tools**: Server health check and API key configuration status
- **Installation tooling**: `setup.sh`, Makefile, CI/CD with GitHub Actions
- **Test suite**: Unit and integration tests covering extractors, campaigns, clients, rules, STIX, context, cache, correlation, FreshRSS
