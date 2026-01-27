# Changelog

## [Unreleased] - 2026-01-27

### Added

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

- **Comprehensive Claude Code permissions** (`.claude/settings.local.json`): Pre-authorized 100+ MCP tool permissions across 12 categories:
  - CVE & vulnerability tools (5)
  - IOC extraction & STIX export (2)
  - Threat intelligence sources: OTX, URLhaus, MalwareBazaar, ThreatFox (13)
  - Detection rule generation: YARA, Sigma network/DNS/firewall (4)
  - Context management & investigations (8)
  - Shodan reconnaissance (5)
  - MITRE ATT&CK lookups (6)
  - Campaign tracking (10)
  - FreshRSS feed integration (6)
  - Health & API key management (2)
  - Local web fetch tools (3)
  - WHOIS/RIR tools: RIPE, ARIN, APNIC, AfriNIC, LACNIC (14)
  - Maigret username search (2)

### Changed

- **Campaign correlation** (`src/osint_agent/correlation.py`): `correlate_campaign_iocs()` now uses `parallel_collect_sets()` to find related campaigns concurrently. Previously sequential (50 IOCs at ~100ms each = 5s), now parallelized with 20 workers (~250ms).

- **FreshRSS IOC extraction** (`mcp-server/tools/freshrss_tools.py`): `freshrss_extract_iocs()` now uses `parallel_filter_map()` to process feed entries concurrently. Previously sequential (50 entries at ~200ms = 10s), now parallelized with 10 workers (~1-2s).
