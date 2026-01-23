# Cyber Security OSINT Agent - Implementation Proposal

## Overview

This document outlines a plan to build an agent-based system for analyzing publicly available information about vulnerabilities and ongoing cyber attacks. The system leverages Claude Code hooks for deterministic control and integrates multiple OSINT (Open Source Intelligence) sources.

**Target User**: Cyber Security Analyst
**Purpose**: Personal security research and threat intelligence gathering
**Foundation**: [claude-code-hooks-mastery](https://github.com/disler/claude-code-hooks-mastery)
**Methodology Reference**: [TSUKUYOMI Intelligence Framework](https://github.com/savannah-i-g/TSUKUYOMI)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Claude Code Agent                            │
├─────────────────────────────────────────────────────────────────┤
│  Hooks Layer                                                     │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│  │ SessionStart │ │ PreToolUse   │ │ PostToolUse  │            │
│  │ Context Load │ │ Validation   │ │ IOC Extract  │            │
│  └──────────────┘ └──────────────┘ └──────────────┘            │
│  ┌──────────────┐ ┌──────────────┐                              │
│  │ Notification │ │ PreCompact   │                              │
│  │ Alerts       │ │ Backup       │                              │
│  └──────────────┘ └──────────────┘                              │
├─────────────────────────────────────────────────────────────────┤
│  Custom Tools / MCP Server                                       │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐   │
│  │ CVE Lookup │ │ IOC Enrich │ │ Threat Feed│ │ Rule Gen   │   │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│  OSINT Data Sources                                              │
│  NVD │ CISA KEV │ AlienVault OTX │ Abuse.ch │ Shodan │ VT      │
└─────────────────────────────────────────────────────────────────┘
```

---

## TSUKUYOMI Framework Integration

The [TSUKUYOMI Intelligence Framework](https://github.com/savannah-i-g/TSUKUYOMI) provides professional-grade intelligence analysis methodologies that significantly enhance our OSINT agent capabilities. The following concepts are adapted from TSUKUYOMI for integration into this project.

### Key Concepts Adopted from TSUKUYOMI

#### 1. Modular JSON Schema Architecture

TSUKUYOMI uses standardized `.tsukuyomi` JSON modules with consistent structure. We adopt this pattern for our tool definitions:

```json
{
  "module_id": "cve_analysis",
  "version": "1.0.0",
  "type": "intelligence_collection",
  "description": "Systematic CVE analysis and triage",
  "dependencies": ["data_ingestion"],
  "input_schema": {
    "cve_id": {"type": "string", "required": true},
    "include_enrichment": {"type": "boolean", "default": true}
  },
  "output_schema": {
    "analysis_result": "object",
    "confidence_score": "number",
    "source_attribution": "array"
  },
  "execution_sequence": ["validate", "collect", "analyze", "synthesize", "report"]
}
```

#### 2. Structured Output Markers

Adopt TSUKUYOMI's standardized output tagging for consistent, parseable results:

| Marker | Purpose | Example |
|--------|---------|---------|
| `//RESULT` | Primary findings | `//RESULT: CVE-2024-1234 confirmed critical` |
| `//QUERY` | Follow-up questions | `//QUERY: Need vendor confirmation on patch availability` |
| `//ANOMALY` | Unexpected findings | `//ANOMALY: Unusual activity spike from this IP` |
| `//CRITICAL` | Priority escalation | `//CRITICAL: Active exploitation detected` |
| `//CONFIDENCE` | Certainty level | `//CONFIDENCE: HIGH (85%) - Multiple corroborating sources` |
| `//SOURCE` | Attribution | `//SOURCE: NVD, CISA KEV, OTX (3 sources)` |

#### 3. Five-Tier Context Hierarchy

Adopt TSUKUYOMI's context management for maintaining analytical state:

```
┌─────────────────────────────────────────────────────────────┐
│ STRATEGIC CONTEXT (Cross-Session)                           │
│ Long-term objectives, threat landscape trends, campaigns    │
├─────────────────────────────────────────────────────────────┤
│ OPERATIONAL CONTEXT (Mission-Duration)                      │
│ Current investigation scope, stakeholder requirements       │
├─────────────────────────────────────────────────────────────┤
│ TACTICAL CONTEXT (Task-Based)                               │
│ Immediate priorities, active module states, working IOCs    │
├─────────────────────────────────────────────────────────────┤
│ TECHNICAL CONTEXT (Operation-Based)                         │
│ API parameters, query specifications, tool configurations   │
├─────────────────────────────────────────────────────────────┤
│ SECURITY CONTEXT (Session-Based)                            │
│ Data handling rules, source sensitivity, sharing boundaries │
└─────────────────────────────────────────────────────────────┘
```

**Implementation**: Store context in `data/context/` with separate files per tier:
- `strategic_context.json` - Persistent across all sessions
- `operational_context.json` - Current investigation/project
- `tactical_context.json` - Current session working state

#### 4. Entity Extraction Categories

Expand IOC extraction to include TSUKUYOMI's five entity types:

| Entity Type | Attributes | Examples |
|-------------|------------|----------|
| **Person** | Name, alias, role, affiliation, clearance | Threat actors, researchers, vendors |
| **Organization** | Name, type, structure, mission, capabilities | APT groups, vendors, agencies |
| **Location** | Coordinates, address, purpose, significance | C2 servers, infrastructure, targets |
| **Technical** | Specifications, deployment, status | Malware, exploits, tools, CVEs |
| **Pattern** | Frequency, participants, routes, transactions | TTPs, campaigns, behaviors |

**Enhanced IOC Schema**:
```json
{
  "entity_id": "uuid",
  "type": "technical",
  "subtype": "malware_hash",
  "value": "a1b2c3d4...",
  "confidence": 0.95,
  "first_seen": "2024-01-15T10:30:00Z",
  "last_seen": "2024-01-15T14:22:00Z",
  "sources": ["VirusTotal", "MalwareBazaar"],
  "related_entities": ["entity_uuid_1", "entity_uuid_2"],
  "tags": ["ransomware", "lockbit", "initial_access"],
  "context": {
    "campaign": "Operation XYZ",
    "threat_actor": "APT-XX"
  }
}
```

#### 5. Intelligence Discipline Alignment

Categorize collection activities using TSUKUYOMI's discipline taxonomy:

| Discipline | Description | Our Implementation |
|------------|-------------|-------------------|
| **Search Engine Intel** | Public search results | WebFetch to security blogs |
| **Social Media Intel** | Platform analysis | Twitter/X security researchers |
| **Public Records** | Official documentation | NVD, CISA, vendor advisories |
| **Data Broker Intel** | Commercial threat data | VirusTotal, Shodan |
| **Metadata Forensics** | File/network metadata | Hash analysis, WHOIS |
| **Domain/Network Enum** | Infrastructure analysis | DNS, IP reputation |
| **GEOINT** | Geographic intelligence | IP geolocation, hosting analysis |
| **Visual Media Analysis** | Image/video examination | Screenshot analysis, CAPTCHA bypass detection |

#### 6. Multi-Step Execution Sequences

Adopt TSUKUYOMI's structured workflow approach. Example for CVE Analysis:

```
┌────────────────────────────────────────────────────────────────┐
│ CVE ANALYSIS EXECUTION SEQUENCE (10 Steps)                     │
├────────────────────────────────────────────────────────────────┤
│ 1. DISCLAIMER     │ Issue analysis limitations, scope bounds   │
│ 2. VALIDATION     │ Verify CVE ID format, check existence      │
│ 3. PRIMARY FETCH  │ NVD API query, retrieve base details       │
│ 4. KEV CHECK      │ Cross-reference CISA KEV for exploitation  │
│ 5. ENRICHMENT     │ Vendor advisories, security blogs, PoCs    │
│ 6. ENTITY EXTRACT │ Pull affected products, versions, CPEs     │
│ 7. PATTERN DETECT │ Link to campaigns, threat actors, malware  │
│ 8. SYNTHESIS      │ Combine all sources, resolve conflicts     │
│ 9. GAP ANALYSIS   │ Identify missing info, suggest follow-ups  │
│ 10. REPORT        │ Structured output with confidence scores   │
└────────────────────────────────────────────────────────────────┘
```

#### 7. Source Assessment Methodology

Implement TSUKUYOMI's credibility evaluation for all collected intelligence:

```python
SOURCE_RELIABILITY = {
    "A": "Completely reliable (official government sources)",
    "B": "Usually reliable (established security vendors)",
    "C": "Fairly reliable (reputable researchers/blogs)",
    "D": "Not usually reliable (unverified social media)",
    "E": "Unreliable (anonymous/suspicious sources)",
    "F": "Reliability cannot be judged"
}

INFORMATION_CREDIBILITY = {
    "1": "Confirmed by independent sources",
    "2": "Probably true (logical, consistent)",
    "3": "Possibly true (reasonable but unconfirmed)",
    "4": "Doubtful (inconsistent, questionable)",
    "5": "Improbable (contradicts known facts)",
    "6": "Truth cannot be judged"
}

# Example: "B2" = Usually reliable source, probably true information
```

#### 8. Quality Assurance Gates

Implement validation checkpoints throughout analysis with **concrete pass/fail criteria**:

| Gate | Timing | Checks | Pass Criteria |
|------|--------|--------|---------------|
| **Pre-Execution** | Before tool calls | Input validation, rate limits, source approval | All inputs match schema; rate limit ≥20% remaining; domain in allowlist |
| **During-Execution** | After each step | Data quality, anomaly detection, timeout handling | Response time <30s; HTTP 2xx status; JSON parseable; no null required fields |
| **Post-Execution** | After completion | Completeness check, confidence calibration, gap identification | ≥80% required fields populated; ≥2 sources consulted; confidence ≥0.6 |

**Quality Gate Implementation**:
```python
# src/osint_agent/quality_gates.py
from dataclasses import dataclass
from typing import Optional

@dataclass
class QualityGateResult:
    passed: bool
    gate_name: str
    checks_passed: int
    checks_total: int
    failures: list[str]
    warnings: list[str]


def pre_execution_gate(module_id: str, inputs: dict, schema: dict) -> QualityGateResult:
    """Validate inputs before execution."""
    failures = []
    warnings = []

    # 1. Schema validation
    required_fields = [k for k, v in schema.items() if v.get("required")]
    for field in required_fields:
        if field not in inputs or inputs[field] is None:
            failures.append(f"Missing required field: {field}")

    # 2. Format validation (e.g., CVE pattern)
    if "cve_id" in inputs:
        import re
        if not re.match(r"^CVE-\d{4}-\d{4,7}$", inputs["cve_id"]):
            failures.append(f"Invalid CVE format: {inputs['cve_id']}")

    # 3. Rate limit check (must have 20% headroom)
    from osint_agent.rate_limiter import get_remaining_quota
    for source in inputs.get("sources", []):
        remaining = get_remaining_quota(source)
        if remaining < 0.2:
            if remaining < 0.05:
                failures.append(f"Rate limit critical for {source}: {remaining:.0%} remaining")
            else:
                warnings.append(f"Rate limit low for {source}: {remaining:.0%} remaining")

    checks_total = len(required_fields) + 2  # schema + format + rate limit
    checks_passed = checks_total - len(failures)

    return QualityGateResult(
        passed=len(failures) == 0,
        gate_name="pre_execution",
        checks_passed=checks_passed,
        checks_total=checks_total,
        failures=failures,
        warnings=warnings,
    )


def post_execution_gate(result: dict, expected_fields: list[str], min_sources: int = 2) -> QualityGateResult:
    """Validate output completeness and quality."""
    failures = []
    warnings = []

    # 1. Field completeness (≥80% required)
    populated = sum(1 for f in expected_fields if result.get(f) is not None)
    completeness = populated / len(expected_fields) if expected_fields else 1.0
    if completeness < 0.8:
        failures.append(f"Insufficient field completeness: {completeness:.0%} (need ≥80%)")
    elif completeness < 0.95:
        warnings.append(f"Some fields missing: {completeness:.0%}")

    # 2. Source count
    sources = result.get("sources", []) or result.get("source_attribution", [])
    if len(sources) < min_sources:
        failures.append(f"Insufficient sources: {len(sources)} (need ≥{min_sources})")

    # 3. Confidence threshold
    confidence = result.get("confidence", result.get("confidence_score", 0))
    if confidence < 0.6:
        failures.append(f"Low confidence: {confidence:.2f} (need ≥0.6)")
    elif confidence < 0.75:
        warnings.append(f"Moderate confidence: {confidence:.2f}")

    # 4. Intelligence gaps flagged
    gaps = result.get("intelligence_gaps", [])
    if gaps:
        warnings.append(f"{len(gaps)} intelligence gaps identified")

    checks_total = 4
    checks_passed = checks_total - len(failures)

    return QualityGateResult(
        passed=len(failures) == 0,
        gate_name="post_execution",
        checks_passed=checks_passed,
        checks_total=checks_total,
        failures=failures,
        warnings=warnings,
    )
```

---

## Phase 0: Testing & Quality Infrastructure

### 0.1 Testing Strategy

**Principle**: Every IOC pattern, API client, and workflow must have tests before implementation.

#### Unit Tests
```python
# tests/test_ioc_extraction.py
import pytest
from osint_agent.extractors import extract_iocs

class TestIOCExtraction:
    """Test IOC pattern matching with known good/bad inputs."""

    @pytest.mark.parametrize("input,expected_type,expected_value", [
        ("Check 192.168.1.1 for activity", "ipv4", "192.168.1.1"),
        ("Hash: a]1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", "md5", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"),
        ("Domain: malware[.]example[.]com", "domain", "malware.example.com"),  # defanged
        ("CVE-2024-12345 is critical", "cve", "CVE-2024-12345"),
    ])
    def test_valid_ioc_extraction(self, input, expected_type, expected_value):
        result = extract_iocs(input)
        assert expected_type in result
        assert expected_value in result[expected_type]

    @pytest.mark.parametrize("input,should_not_match", [
        ("Version 1.0.0 released", "ipv4"),  # Not an IP
        ("file.txt attachment", "domain"),   # Not a domain
        ("abc123 reference", "md5"),         # Too short
    ])
    def test_false_positive_rejection(self, input, should_not_match):
        result = extract_iocs(input)
        assert should_not_match not in result or len(result[should_not_match]) == 0

    def test_extraction_timeout(self):
        """Regex must complete within 100ms to prevent ReDoS."""
        import time
        malicious_input = "a" * 10000  # Potential ReDoS payload
        start = time.time()
        extract_iocs(malicious_input)
        assert time.time() - start < 0.1
```

#### Integration Tests (with mocks)
```python
# tests/test_api_clients.py
import pytest
from unittest.mock import patch, MagicMock
from osint_agent.clients import NVDClient, CISAKEVClient

class TestNVDClient:
    @patch('requests.get')
    def test_cve_lookup_success(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"vulnerabilities": [{"cve": {"id": "CVE-2024-1234"}}]}
        )
        client = NVDClient()
        result = client.lookup("CVE-2024-1234")
        assert result["cve_id"] == "CVE-2024-1234"

    @patch('requests.get')
    def test_cve_lookup_rate_limited(self, mock_get):
        mock_get.return_value = MagicMock(status_code=429)
        client = NVDClient()
        with pytest.raises(RateLimitError):
            client.lookup("CVE-2024-1234")

    @patch('requests.get')
    def test_cve_lookup_timeout(self, mock_get):
        mock_get.side_effect = requests.Timeout()
        client = NVDClient()
        with pytest.raises(APITimeoutError):
            client.lookup("CVE-2024-1234")
```

#### End-to-End Workflow Tests
```python
# tests/test_workflows.py
class TestDailyBriefWorkflow:
    """Test complete workflow with recorded API responses."""

    @pytest.fixture
    def vcr_config(self):
        return {"record_mode": "none", "cassette_library_dir": "tests/cassettes"}

    @pytest.mark.vcr()
    def test_daily_brief_generation(self):
        """Replay recorded API responses to test full workflow."""
        from osint_agent.workflows import generate_daily_brief
        result = generate_daily_brief(watchlist=["Microsoft", "Cisco"])

        assert "critical_cves" in result
        assert "kev_additions" in result
        assert "watchlist_alerts" in result
        assert result["confidence"] >= 0.7
```

### 0.2 CI/CD Configuration

**File**: `.github/workflows/ci.yml`
```yaml
name: OSINT Agent CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v4

      - name: Install dependencies
        run: uv sync --dev

      - name: Lint
        run: uv run ruff check .

      - name: Type check
        run: uv run mypy src/

      - name: Unit tests
        run: uv run pytest tests/unit -v --cov=osint_agent

      - name: Integration tests
        run: uv run pytest tests/integration -v
        env:
          USE_MOCKS: "true"
```

**File**: `pyproject.toml` (dev dependencies)
```toml
[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-cov>=4.0",
    "pytest-timeout>=2.0",
    "pytest-vcr>=1.0",
    "ruff>=0.4",
    "mypy>=1.10",
    "responses>=0.25",  # HTTP mocking
]
```

### 0.3 Pre-commit Hooks

**File**: `.pre-commit-config.yaml`
```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.0
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.10.0
    hooks:
      - id: mypy
        additional_dependencies: [types-requests]
```

---

## Phase 1: Foundation Setup

### 1.1 Prerequisites

- Python 3.11+
- [UV](https://github.com/astral-sh/uv) package manager
- Claude Code CLI installed and configured
- API keys for OSINT services (see Section 4)
- `keyring` library for secure credential storage

### 1.2 Clone the Hooks Framework

```bash
git clone https://github.com/disler/claude-code-hooks-mastery
cd claude-code-hooks-mastery
```

### 1.3 Directory Structure

```
SecurityResearch/
├── src/osint_agent/              # Main package
│   ├── __init__.py
│   ├── extractors.py             # IOC extraction with validation
│   ├── clients/                  # API clients with error handling
│   │   ├── __init__.py
│   │   ├── nvd.py
│   │   ├── cisa_kev.py
│   │   ├── otx.py
│   │   └── abuse_ch.py
│   ├── cache.py                  # TTL-based caching layer
│   └── workflows.py              # High-level workflow orchestration
├── hooks/                        # Claude Code hooks
│   ├── session_start.py          # Load threat context (non-blocking)
│   ├── pre_tool_use.py           # Validate OSINT queries
│   ├── post_tool_use.py          # Extract IOCs/entities
│   └── notification.py           # Alert on critical findings
├── mcp-server/                   # Optional MCP server
│   ├── tools/
│   └── server.py
├── config/
│   ├── modules/                  # TSUKUYOMI-style module definitions
│   │   ├── schema.json           # JSON Schema for module validation
│   │   ├── cve_analysis.json
│   │   ├── ioc_enrichment.json
│   │   └── webint_collection.json
│   ├── templates/                # Output templates
│   │   ├── threat_brief.md
│   │   ├── cve_report.md
│   │   └── incident_report.md
│   ├── allowed_domains.json      # Configurable domain allowlist
│   ├── source_reliability.json   # Source rating definitions
│   └── watchlist.json            # Products/vendors to monitor
├── data/
│   ├── context/                  # TSUKUYOMI context hierarchy (git-tracked)
│   │   ├── strategic.json        # Cross-session context
│   │   ├── operational.json      # Mission-duration context
│   │   └── tactical.json         # Task-based context (gitignored)
│   ├── cache/                    # API response cache (gitignored)
│   │   └── .gitkeep
│   ├── iocs.db                   # SQLite IOC database
│   └── logs/                     # Structured JSON logs
│       └── .gitkeep
├── backups/                      # Automated backups (gitignored)
│   └── .gitkeep
├── tests/
│   ├── unit/
│   ├── integration/
│   └── cassettes/                # VCR recorded API responses
├── pyproject.toml
├── .pre-commit-config.yaml
└── .gitignore
```

**Note**: Simplified from v1.1 - removed separate `templates/` and `modules/` top-level dirs; consolidated under `config/`. Entity storage moved to SQLite (see `iocs.db` schema in Appendix A).

---

## Phase 2: Core Capabilities

### 2.1 Capability Matrix

| Capability | Description | Implementation | Priority |
|------------|-------------|----------------|----------|
| CVE Lookup | Query vulnerability databases for CVE details | Custom Tool/MCP | High |
| Threat Feed Aggregation | Aggregate data from multiple threat intel sources | SessionStart Hook | High |
| IOC Extraction | Parse IPs, domains, hashes from analyzed content | PostToolUse Hook | High |
| Detection Rule Generation | Create YARA/Sigma rules from threat descriptions | Custom Skill | Medium |
| Exposure Analysis | Check internet-facing assets via Shodan | Custom Tool/MCP | Medium |
| News Monitoring | Fetch security blogs and vendor advisories | Custom Tool | Medium |
| Reputation Lookup | Check IOCs against reputation databases | Custom Tool/MCP | High |
| Watchlist Alerting | Notify when monitored products have new CVEs | Notification Hook | Medium |

### 2.2 Capability Details

#### CVE Lookup
- Query NVD API for vulnerability details
- Retrieve CVSS scores, affected products, references
- Check exploitation status in CISA KEV
- Find related security advisories

#### IOC Extraction
- Automatically parse from text/web content:
  - IPv4/IPv6 addresses
  - Domain names and URLs
  - File hashes (MD5, SHA1, SHA256)
  - CVE identifiers (CVE-YYYY-NNNNN)
  - Email addresses
- Store in structured format for correlation

#### Threat Feed Aggregation
- Pull latest data on session start
- Merge data from multiple sources
- Deduplicate and normalize entries
- Inject relevant context into session

---

## Phase 3: Hook Implementations

### 3.1 SessionStart Hook - Threat Context Loader

**File**: `hooks/session_start.py`

**Purpose**: Load current threat landscape context when starting a security research session.

**Design Principles**:
- **Non-blocking**: Return cached data immediately; refresh in background
- **Graceful degradation**: Session starts even if APIs are down
- **Cache-first**: TTL-based caching reduces API load and startup latency

**Functionality**:
```python
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from osint_agent.clients import NVDClient, CISAKEVClient
from osint_agent.cache import ThreatContextCache

logger = logging.getLogger(__name__)

# Configuration
CACHE_DIR = Path("data/cache")
CACHE_TTL_HOURS = 1
FETCH_TIMEOUT_SECONDS = 5  # Max time to wait for fresh data
BACKGROUND_REFRESH = True

cache = ThreatContextCache(CACHE_DIR, ttl_hours=CACHE_TTL_HOURS)


def on_session_start() -> dict:
    """Load threat context with cache-first strategy."""

    # 1. Always return cached data immediately if available
    cached_context = cache.get("threat_context")
    if cached_context and not cache.is_stale("threat_context"):
        logger.info("Returning fresh cached threat context")
        return {"context": cached_context}

    # 2. If cache is stale but exists, return it and refresh in background
    if cached_context:
        logger.info("Returning stale cache, triggering background refresh")
        if BACKGROUND_REFRESH:
            _trigger_background_refresh()
        return {"context": cached_context}

    # 3. No cache - try to fetch with timeout (don't block session start)
    try:
        context = _fetch_threat_context_with_timeout(FETCH_TIMEOUT_SECONDS)
        cache.set("threat_context", context)
        return {"context": context}
    except TimeoutError:
        logger.warning("Threat context fetch timed out, starting without context")
        _trigger_background_refresh()
        return {"context": _get_fallback_context()}
    except Exception as e:
        logger.error(f"Failed to fetch threat context: {e}")
        return {"context": _get_fallback_context()}


def _fetch_threat_context_with_timeout(timeout: int) -> str:
    """Fetch threat context with hard timeout."""
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_fetch_threat_context)
        return future.result(timeout=timeout)


def _fetch_threat_context() -> str:
    """Fetch and format threat context from APIs."""
    context_parts = []

    try:
        # Fetch CISA KEV (usually fast, static JSON file)
        kev_client = CISAKEVClient()
        kev_updates = kev_client.get_recent(days=7)
        context_parts.append(f"- {len(kev_updates)} new CISA KEV entries this week")
    except Exception as e:
        logger.warning(f"KEV fetch failed: {e}")
        context_parts.append("- CISA KEV: unavailable")

    try:
        # Fetch critical CVEs (can be slow)
        nvd_client = NVDClient()
        critical_cves = nvd_client.get_critical(cvss_min=8.0, days=7)
        context_parts.append(f"- {len(critical_cves)} critical CVEs (CVSS 8.0+) this week")

        # Check watchlist
        watchlist = _load_watchlist()
        alerts = _check_watchlist(watchlist, critical_cves)
        if alerts:
            context_parts.append(f"- ⚠️ ALERT: {len(alerts)} CVEs affect your watchlist")
            for alert in alerts[:3]:  # Top 3 only
                context_parts.append(f"  - {alert['cve_id']}: {alert['product']}")
    except Exception as e:
        logger.warning(f"NVD fetch failed: {e}")
        context_parts.append("- NVD CVEs: unavailable")

    header = f"[THREAT CONTEXT - {datetime.now().strftime('%Y-%m-%d %H:%M')}]"
    return header + "\n" + "\n".join(context_parts)


def _trigger_background_refresh():
    """Spawn background process to refresh cache."""
    import subprocess
    subprocess.Popen(
        ["uv", "run", "python", "-m", "osint_agent.refresh_cache"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _get_fallback_context() -> str:
    """Minimal context when APIs unavailable."""
    return (
        f"[THREAT CONTEXT - {datetime.now().strftime('%Y-%m-%d %H:%M')}]\n"
        "- Threat feeds unavailable - check API connectivity\n"
        "- Tip: Run `osint refresh` to manually update cache"
    )


def _load_watchlist() -> list:
    watchlist_path = Path("config/watchlist.json")
    if watchlist_path.exists():
        return json.loads(watchlist_path.read_text())
    return {"vendors": [], "products": []}


def _check_watchlist(watchlist: dict, cves: list) -> list:
    """Match CVEs against watchlist products/vendors."""
    alerts = []
    watch_terms = set(
        [v.lower() for v in watchlist.get("vendors", [])] +
        [p.lower() for p in watchlist.get("products", [])]
    )
    for cve in cves:
        for product in cve.get("affected_products", []):
            if any(term in product.lower() for term in watch_terms):
                alerts.append({"cve_id": cve["id"], "product": product})
    return alerts
```

**Cache Implementation**:
```python
# src/osint_agent/cache.py
import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Any


class ThreatContextCache:
    """TTL-based file cache for API responses."""

    def __init__(self, cache_dir: Path, ttl_hours: int = 1):
        self.cache_dir = cache_dir
        self.ttl = timedelta(hours=ttl_hours)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, key: str) -> Path:
        return self.cache_dir / f"{key}.json"

    def get(self, key: str) -> Optional[str]:
        path = self._cache_path(key)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            return data.get("value")
        except (json.JSONDecodeError, KeyError):
            return None

    def is_stale(self, key: str) -> bool:
        path = self._cache_path(key)
        if not path.exists():
            return True
        try:
            data = json.loads(path.read_text())
            cached_at = datetime.fromisoformat(data["cached_at"])
            return datetime.now() - cached_at > self.ttl
        except (json.JSONDecodeError, KeyError):
            return True

    def set(self, key: str, value: str) -> None:
        path = self._cache_path(key)
        path.write_text(json.dumps({
            "value": value,
            "cached_at": datetime.now().isoformat(),
        }))
```

**Output Example**:
```
[THREAT CONTEXT - 2024-01-15 09:30]
- 3 new CISA KEV entries this week
- 12 critical CVEs (CVSS 8.0+) this week
- ⚠️ ALERT: 2 CVEs affect your watchlist
  - CVE-2024-1234: Microsoft Exchange Server
  - CVE-2024-5678: Cisco IOS XE
```

### 3.2 PreToolUse Hook - Safe OSINT Queries

**File**: `hooks/pre_tool_use.py`

**Purpose**: Validate external queries go only to approved OSINT sources.

**Design Principles**:
- **Configurable allowlist**: Domains managed via JSON config, not hardcoded
- **Rate limiting with backoff**: Per-domain limits with exponential backoff
- **Audit logging**: All blocked requests logged for review

**Configuration File**: `config/allowed_domains.json`
```json
{
  "version": "1.0",
  "last_updated": "2024-01-15",
  "domains": {
    "nvd.nist.gov": {"category": "vuln_db", "rate_limit": 50, "window_seconds": 30},
    "services.nvd.nist.gov": {"category": "vuln_db", "rate_limit": 50, "window_seconds": 30},
    "cve.org": {"category": "vuln_db", "rate_limit": 60, "window_seconds": 60},
    "cveawg.mitre.org": {"category": "vuln_db", "rate_limit": 60, "window_seconds": 60},
    "cisa.gov": {"category": "official", "rate_limit": 30, "window_seconds": 60},
    "www.cisa.gov": {"category": "official", "rate_limit": 30, "window_seconds": 60},
    "otx.alienvault.com": {"category": "threat_intel", "rate_limit": 100, "window_seconds": 60},
    "urlhaus.abuse.ch": {"category": "threat_intel", "rate_limit": 60, "window_seconds": 60},
    "urlhaus-api.abuse.ch": {"category": "threat_intel", "rate_limit": 60, "window_seconds": 60},
    "bazaar.abuse.ch": {"category": "threat_intel", "rate_limit": 60, "window_seconds": 60},
    "mb-api.abuse.ch": {"category": "threat_intel", "rate_limit": 60, "window_seconds": 60},
    "threatfox.abuse.ch": {"category": "threat_intel", "rate_limit": 60, "window_seconds": 60},
    "threatfox-api.abuse.ch": {"category": "threat_intel", "rate_limit": 60, "window_seconds": 60},
    "www.virustotal.com": {"category": "reputation", "rate_limit": 4, "window_seconds": 60},
    "api.shodan.io": {"category": "exposure", "rate_limit": 10, "window_seconds": 60},
    "api.abuseipdb.com": {"category": "reputation", "rate_limit": 60, "window_seconds": 60},
    "bleepingcomputer.com": {"category": "news", "rate_limit": 10, "window_seconds": 60},
    "www.bleepingcomputer.com": {"category": "news", "rate_limit": 10, "window_seconds": 60},
    "therecord.media": {"category": "news", "rate_limit": 10, "window_seconds": 60},
    "krebsonsecurity.com": {"category": "news", "rate_limit": 10, "window_seconds": 60}
  },
  "admin_notes": "To add domains: edit this file and restart session. Use `osint domains add <domain>` for CLI."
}
```

**Functionality**:
```python
import json
import logging
import time
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Rate limiting state (in-memory, resets on session restart)
_request_timestamps: dict[str, list[float]] = defaultdict(list)


@dataclass
class DomainConfig:
    category: str
    rate_limit: int
    window_seconds: int


def load_allowed_domains() -> dict[str, DomainConfig]:
    """Load domain allowlist from config file."""
    config_path = Path("config/allowed_domains.json")
    if not config_path.exists():
        logger.error("allowed_domains.json not found - blocking all external requests")
        return {}

    try:
        config = json.loads(config_path.read_text())
        return {
            domain: DomainConfig(**settings)
            for domain, settings in config.get("domains", {}).items()
        }
    except (json.JSONDecodeError, TypeError) as e:
        logger.error(f"Failed to parse allowed_domains.json: {e}")
        return {}


def extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL, handling edge cases."""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower().split(":")[0]  # Remove port if present
    except Exception:
        return None


def check_rate_limit(domain: str, config: DomainConfig) -> tuple[bool, str]:
    """Check if domain is within rate limits. Returns (allowed, reason)."""
    now = time.time()
    window_start = now - config.window_seconds

    # Clean old timestamps
    _request_timestamps[domain] = [
        ts for ts in _request_timestamps[domain] if ts > window_start
    ]

    if len(_request_timestamps[domain]) >= config.rate_limit:
        wait_time = int(config.window_seconds - (now - _request_timestamps[domain][0]))
        return False, f"Rate limit ({config.rate_limit}/{config.window_seconds}s) exceeded. Wait {wait_time}s."

    _request_timestamps[domain].append(now)
    return True, ""


def on_pre_tool_use(tool_name: str, tool_input: dict) -> dict:
    """Validate tool usage before execution."""

    if tool_name != "WebFetch":
        return {"blocked": False}

    url = tool_input.get("url", "")
    domain = extract_domain(url)

    if not domain:
        logger.warning(f"Could not parse domain from URL: {url}")
        return {
            "blocked": True,
            "reason": f"Invalid URL format: {url}"
        }

    # Load allowlist (cached after first load in production)
    allowed_domains = load_allowed_domains()

    if domain not in allowed_domains:
        logger.warning(f"Blocked request to non-approved domain: {domain}")
        _log_blocked_request(domain, url, "not_in_allowlist")
        return {
            "blocked": True,
            "reason": f"Domain '{domain}' not in approved OSINT sources. "
                      f"Add to config/allowed_domains.json if legitimate."
        }

    # Check rate limit
    config = allowed_domains[domain]
    allowed, reason = check_rate_limit(domain, config)

    if not allowed:
        logger.warning(f"Rate limited: {domain} - {reason}")
        _log_blocked_request(domain, url, "rate_limited")
        return {"blocked": True, "reason": reason}

    logger.debug(f"Allowed request to {domain} ({config.category})")
    return {"blocked": False}


def _log_blocked_request(domain: str, url: str, reason: str) -> None:
    """Audit log for blocked requests."""
    log_path = Path("data/logs/blocked_requests.jsonl")
    log_path.parent.mkdir(parents=True, exist_ok=True)

    entry = json.dumps({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "domain": domain,
        "url": url[:200],  # Truncate long URLs
        "reason": reason,
    })

    with open(log_path, "a") as f:
        f.write(entry + "\n")
```

### 3.3 PostToolUse Hook - IOC Extractor

**File**: `hooks/post_tool_use.py`

**Purpose**: Automatically extract and catalog IOCs from analyzed content.

**Design Principles**:
- **Accurate patterns**: TLD validation, defang support, false positive reduction
- **Timeout protection**: Regex operations bounded to prevent ReDoS
- **Graceful failure**: Extraction errors don't break the tool pipeline
- **Structured logging**: JSON logs for analysis and debugging

**Functionality**:
```python
import re
import json
import logging
import signal
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional
from contextlib import contextmanager
from functools import lru_cache

logger = logging.getLogger(__name__)

# Configuration
EXTRACTION_TIMEOUT_SECONDS = 2
MAX_CONTENT_LENGTH = 500_000  # 500KB max to prevent memory issues
IOC_DB_PATH = Path("data/iocs.db")
LOG_PATH = Path("data/logs/ioc_extractions.jsonl")

# Valid TLDs for domain validation (top ~50 + common security-relevant ones)
VALID_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int",
    "io", "co", "me", "info", "biz", "xyz", "online", "site", "top",
    "ru", "cn", "de", "uk", "fr", "jp", "br", "in", "it", "nl", "au", "es", "ca",
    "su", "cc", "tk", "ml", "ga", "cf", "gq",  # Common malicious TLDs
    "onion", "bit",  # Special TLDs
}


# Improved patterns with validation
class IOCPatterns:
    """Compiled regex patterns for IOC extraction with validation."""

    # IPv4 with octet range validation (0-255)
    IPV4 = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    # IPv6 (simplified - full and compressed forms)
    IPV6 = re.compile(
        r"\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b|"
        r"\b(?:[a-fA-F0-9]{1,4}:){1,7}:\b|"
        r"\b::(?:[a-fA-F0-9]{1,4}:){0,6}[a-fA-F0-9]{1,4}\b"
    )

    # Domain with TLD validation (handled post-match)
    # Supports defanged: example[.]com, example[dot]com
    DOMAIN = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:[a-zA-Z]{2,})\b|"
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\[?\.\]?|\[dot\]))+"
        r"(?:[a-zA-Z]{2,})\b",
        re.IGNORECASE
    )

    # Hashes - require word boundaries and exact lengths
    MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
    SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
    SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

    # CVE - standard format
    CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

    # URL - supports defanged hxxp(s)
    URL = re.compile(
        r"(?:https?|hxxps?|ftp)://[^\s<>\"'\]]+",
        re.IGNORECASE
    )

    # Email addresses
    EMAIL = re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    )


def refang(text: str) -> str:
    """Convert defanged IOCs back to normal form."""
    return (
        text
        .replace("[.]", ".")
        .replace("[dot]", ".")
        .replace("hxxp", "http")
        .replace("hXXp", "http")
        .replace("[://]", "://")
        .replace("[:]", ":")
        .replace("[@]", "@")
    )


def validate_domain(domain: str) -> bool:
    """Validate domain has known TLD and isn't a false positive."""
    # Refang first
    domain = refang(domain).lower()

    # Extract TLD
    parts = domain.split(".")
    if len(parts) < 2:
        return False

    tld = parts[-1]

    # Check against known TLDs
    if tld not in VALID_TLDS:
        return False

    # Filter common false positives
    false_positives = {
        "example.com", "test.com", "localhost.localdomain",
        "schema.org", "w3.org", "xmlns.com",
    }
    if domain in false_positives:
        return False

    # Filter version strings (v1.2.3 pattern)
    if re.match(r"^v?\d+\.\d+", domain):
        return False

    return True


def validate_ip(ip: str) -> bool:
    """Filter private/reserved IPs that are usually false positives."""
    octets = [int(x) for x in ip.split(".")]

    # Private ranges
    if octets[0] == 10:
        return False
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return False
    if octets[0] == 192 and octets[1] == 168:
        return False
    if octets[0] == 127:  # Loopback
        return False
    if octets[0] == 0:  # Invalid
        return False

    return True


@contextmanager
def timeout_handler(seconds: int):
    """Context manager for regex timeout protection."""
    def _handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds}s")

    # Only works on Unix
    try:
        old_handler = signal.signal(signal.SIGALRM, _handler)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    except (ValueError, AttributeError):
        # Windows or threading issues - just run without timeout
        yield


def extract_iocs(content: str) -> dict[str, list[str]]:
    """Extract IOCs from content with validation and timeout."""

    # Truncate oversized content
    if len(content) > MAX_CONTENT_LENGTH:
        logger.warning(f"Content truncated from {len(content)} to {MAX_CONTENT_LENGTH}")
        content = content[:MAX_CONTENT_LENGTH]

    extracted = {}

    try:
        with timeout_handler(EXTRACTION_TIMEOUT_SECONDS):
            # IPv4
            ipv4_matches = IOCPatterns.IPV4.findall(content)
            valid_ips = [ip for ip in set(ipv4_matches) if validate_ip(ip)]
            if valid_ips:
                extracted["ipv4"] = valid_ips

            # IPv6
            ipv6_matches = IOCPatterns.IPV6.findall(content)
            if ipv6_matches:
                extracted["ipv6"] = list(set(ipv6_matches))

            # Domains (with TLD validation)
            domain_matches = IOCPatterns.DOMAIN.findall(content)
            valid_domains = [
                refang(d) for d in set(domain_matches) if validate_domain(d)
            ]
            if valid_domains:
                extracted["domain"] = valid_domains

            # Hashes
            for hash_type, pattern in [
                ("md5", IOCPatterns.MD5),
                ("sha1", IOCPatterns.SHA1),
                ("sha256", IOCPatterns.SHA256),
            ]:
                matches = pattern.findall(content)
                if matches:
                    # Lowercase for consistency
                    extracted[hash_type] = [h.lower() for h in set(matches)]

            # CVEs
            cve_matches = IOCPatterns.CVE.findall(content)
            if cve_matches:
                extracted["cve"] = [c.upper() for c in set(cve_matches)]

            # URLs
            url_matches = IOCPatterns.URL.findall(content)
            if url_matches:
                extracted["url"] = [refang(u) for u in set(url_matches)]

            # Emails
            email_matches = IOCPatterns.EMAIL.findall(content)
            if email_matches:
                extracted["email"] = list(set(email_matches))

    except TimeoutError:
        logger.error("IOC extraction timed out - possible ReDoS attempt")
    except Exception as e:
        logger.error(f"IOC extraction failed: {e}")

    return extracted


def save_to_ioc_database(iocs: dict[str, list[str]], source: str) -> None:
    """Persist IOCs to SQLite database."""
    IOC_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    try:
        conn = sqlite3.connect(IOC_DB_PATH)
        cursor = conn.cursor()

        # Ensure table exists with indexes
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                hit_count INTEGER DEFAULT 1,
                UNIQUE(type, value)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_first_seen ON iocs(first_seen)")

        now = datetime.utcnow().isoformat() + "Z"

        for ioc_type, values in iocs.items():
            for value in values:
                cursor.execute("""
                    INSERT INTO iocs (type, value, source, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(type, value) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        hit_count = hit_count + 1
                """, (ioc_type, value, source, now, now))

        conn.commit()
        conn.close()
        logger.debug(f"Saved {sum(len(v) for v in iocs.values())} IOCs to database")

    except sqlite3.Error as e:
        logger.error(f"Database error saving IOCs: {e}")


def log_extraction(tool_name: str, iocs: dict[str, list[str]]) -> None:
    """Structured logging for IOC extractions."""
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source_tool": tool_name,
        "ioc_counts": {k: len(v) for k, v in iocs.items()},
        "total_iocs": sum(len(v) for v in iocs.values()),
    }

    try:
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except IOError as e:
        logger.warning(f"Failed to write extraction log: {e}")


def on_post_tool_use(tool_name: str, tool_input: dict, tool_output: str) -> str:
    """Hook entry point - extract IOCs from tool output."""

    if tool_name not in ["WebFetch", "Read"]:
        return tool_output

    try:
        content = str(tool_output)
        extracted_iocs = extract_iocs(content)

        if extracted_iocs:
            source = tool_input.get("url", tool_input.get("file_path", tool_name))
            save_to_ioc_database(extracted_iocs, source)
            log_extraction(tool_name, extracted_iocs)
            logger.info(
                f"Extracted {sum(len(v) for v in extracted_iocs.values())} IOCs "
                f"from {tool_name}: {list(extracted_iocs.keys())}"
            )

    except Exception as e:
        # Never let extraction errors break the tool pipeline
        logger.error(f"IOC extraction hook failed (non-fatal): {e}")

    return tool_output
```

### 3.4 Notification Hook - High-Severity Alerts

**File**: `hooks/notification.py`

**Purpose**: Alert analyst when critical findings are detected.

**Functionality**:
```python
def on_notification(message, level):
    # Check for critical indicators
    critical_keywords = [
        "CVSS 9",
        "CVSS 10",
        "actively exploited",
        "zero-day",
        "critical vulnerability",
        "ransomware",
        "APT",
    ]

    is_critical = any(kw.lower() in message.lower() for kw in critical_keywords)

    if is_critical or level == "critical":
        # Desktop notification
        send_desktop_notification(
            title="Security Alert",
            message=message[:200],
            urgency="critical"
        )

        # Optional: TTS announcement
        if config.get("tts_enabled"):
            speak(f"Critical security alert: {message[:100]}")

        # Log to alerts file
        log_alert(message, level)
```

---

## Phase 4: OSINT Data Sources

### 4.1 Vulnerability Databases

| Source | API Endpoint | Auth Required | Rate Limit |
|--------|--------------|---------------|------------|
| NVD | `https://services.nvd.nist.gov/rest/json/cves/2.0` | API Key (recommended) | 5 req/30s (no key), 50 req/30s (with key) |
| CVE.org | `https://cveawg.mitre.org/api/cve/` | No | Reasonable use |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | No | N/A (static file) |

### 4.2 Threat Intelligence Feeds

| Source | API Endpoint | Auth Required | Free Tier |
|--------|--------------|---------------|-----------|
| AlienVault OTX | `https://otx.alienvault.com/api/` | API Key | Yes (generous) |
| URLhaus | `https://urlhaus-api.abuse.ch/v1/` | No | Yes |
| MalwareBazaar | `https://mb-api.abuse.ch/api/v1/` | No | Yes |
| ThreatFox | `https://threatfox-api.abuse.ch/api/v1/` | No | Yes |
| VirusTotal | `https://www.virustotal.com/api/v3/` | API Key | Limited (500 req/day) |
| AbuseIPDB | `https://api.abuseipdb.com/api/v2/` | API Key | Yes (1000 req/day) |

### 4.3 Exposure Analysis

| Source | API Endpoint | Auth Required | Free Tier |
|--------|--------------|---------------|-----------|
| Shodan | `https://api.shodan.io/` | API Key | Limited |
| Censys | `https://search.censys.io/api` | API Key | Limited |

### 4.4 Security News & Advisories

| Source | URL | Type |
|--------|-----|------|
| BleepingComputer | `https://www.bleepingcomputer.com/` | News |
| The Record | `https://therecord.media/` | News |
| Krebs on Security | `https://krebsonsecurity.com/` | Blog |
| Microsoft Security | `https://msrc.microsoft.com/update-guide/` | Advisories |
| Cisco Security | `https://sec.cloudapps.cisco.com/security/center/publicationListing.x` | Advisories |

### 4.5 API Key Management

**⚠️ Security-Critical**: API keys provide access to paid services and may expose your research activity. Use secure storage.

#### Recommended: System Keychain (via `keyring`)

Store keys in your OS's secure credential store (macOS Keychain, Windows Credential Locker, Linux Secret Service):

```python
# src/osint_agent/credentials.py
import keyring
import os
from typing import Optional

SERVICE_NAME = "osint-agent"

# Key identifiers
KEYS = {
    "NVD_API_KEY": "nvd",
    "OTX_API_KEY": "otx",
    "VT_API_KEY": "virustotal",
    "ABUSEIPDB_API_KEY": "abuseipdb",
    "SHODAN_API_KEY": "shodan",
}


def get_api_key(key_name: str) -> Optional[str]:
    """Retrieve API key from secure storage or environment."""
    # 1. Check environment variable first (for CI/containers)
    env_value = os.environ.get(key_name)
    if env_value:
        return env_value

    # 2. Check system keychain
    service_key = KEYS.get(key_name)
    if service_key:
        try:
            value = keyring.get_password(SERVICE_NAME, service_key)
            if value:
                return value
        except keyring.errors.KeyringError as e:
            print(f"Keyring error: {e}")

    return None


def set_api_key(key_name: str, value: str) -> bool:
    """Store API key in system keychain."""
    service_key = KEYS.get(key_name)
    if not service_key:
        print(f"Unknown key: {key_name}")
        return False

    try:
        keyring.set_password(SERVICE_NAME, service_key, value)
        print(f"✓ Stored {key_name} in system keychain")
        return True
    except keyring.errors.KeyringError as e:
        print(f"✗ Failed to store key: {e}")
        return False


def delete_api_key(key_name: str) -> bool:
    """Remove API key from system keychain."""
    service_key = KEYS.get(key_name)
    if not service_key:
        return False

    try:
        keyring.delete_password(SERVICE_NAME, service_key)
        return True
    except keyring.errors.KeyringError:
        return False


def list_configured_keys() -> list[str]:
    """List which API keys are configured."""
    configured = []
    for key_name, service_key in KEYS.items():
        if get_api_key(key_name):
            configured.append(key_name)
    return configured
```

#### CLI for Key Management

```bash
# Set up API keys (interactive, masked input)
osint keys set NVD_API_KEY
osint keys set OTX_API_KEY
osint keys set VT_API_KEY

# List configured keys (values not shown)
osint keys list
# Output:
# ✓ NVD_API_KEY: configured
# ✓ OTX_API_KEY: configured
# ✗ VT_API_KEY: not configured
# ✗ SHODAN_API_KEY: not configured

# Remove a key
osint keys delete VT_API_KEY
```

#### Fallback: Environment Variables (for CI/Docker)

For containerized deployments, use environment variables:

```bash
# .env.example (committed - template only)
NVD_API_KEY=
OTX_API_KEY=
VT_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=

# Never commit actual keys - use CI secrets or Docker secrets
```

```yaml
# docker-compose.yml
services:
  osint-agent:
    environment:
      - NVD_API_KEY=${NVD_API_KEY}
      - OTX_API_KEY=${OTX_API_KEY}
    # Or use Docker secrets for production
    secrets:
      - nvd_api_key
```

#### Security Checklist

- [ ] **Never** commit keys to git (add `*.env` to `.gitignore`)
- [ ] Use system keychain for local development
- [ ] Use CI/CD secrets for automated pipelines
- [ ] Rotate keys quarterly or after suspected exposure
- [ ] Use read-only API scopes where available (e.g., VirusTotal)
- [ ] Monitor API usage dashboards for anomalies

---

## Phase 5: MCP Server (Optional)

### 5.1 Purpose

An MCP (Model Context Protocol) server provides Claude with direct access to custom security tools, offering:
- Structured tool interfaces
- Better error handling
- Cleaner separation of concerns
- Reusable across projects

### 5.2 Proposed Tools

```
mcp-server/
├── server.py
└── tools/
    ├── cve_lookup.py        # Query CVE databases
    ├── ioc_enrich.py        # Enrich IOCs with reputation data
    ├── shodan_query.py      # Internet exposure analysis
    ├── threat_feed.py       # Query threat intel feeds
    └── rule_generator.py    # Generate YARA/Sigma rules
```

### 5.3 Tool Specifications

#### cve_lookup

```json
{
  "name": "cve_lookup",
  "description": "Look up CVE details from NVD and related sources",
  "parameters": {
    "cve_id": "CVE identifier (e.g., CVE-2024-1234)",
    "include_kev": "Check if in CISA KEV (default: true)",
    "include_references": "Include external references (default: true)"
  },
  "returns": {
    "cve_id": "string",
    "description": "string",
    "cvss_score": "number",
    "cvss_vector": "string",
    "affected_products": "array",
    "in_kev": "boolean",
    "exploitation_status": "string",
    "references": "array",
    "published_date": "string",
    "last_modified": "string"
  }
}
```

#### ioc_enrich

```json
{
  "name": "ioc_enrich",
  "description": "Enrich an IOC with reputation data from multiple sources",
  "parameters": {
    "ioc": "The IOC to enrich (IP, domain, hash, URL)",
    "ioc_type": "Type of IOC (auto-detected if not specified)",
    "sources": "Sources to query (default: all available)"
  },
  "returns": {
    "ioc": "string",
    "type": "string",
    "reputation_score": "number",
    "malicious": "boolean",
    "tags": "array",
    "first_seen": "string",
    "last_seen": "string",
    "source_results": "object"
  }
}
```

---

## Phase 6: Example Workflows

### 6.1 Daily Threat Brief

**Prompt**:
```
Generate a daily threat brief covering:
1. New critical vulnerabilities (CVSS 8.0+) from the past 24 hours
2. Any additions to CISA KEV
3. Active threat campaigns from OTX
4. Highlight anything affecting my watchlist
```

**Expected Output**:
- Summary of critical CVEs with affected products
- KEV additions with due dates
- Active campaigns with IOCs
- Watchlist alerts with recommended actions

### 6.2 Incident Investigation

**Prompt**:
```
Investigate these IOCs from our SIEM alert:
- IP: 192.0.2.100
- Domain: malicious-example.com
- Hash: a1b2c3d4e5f6...

Check reputation, find related IOCs, and generate detection rules.
```

**Expected Output**:
- Reputation data for each IOC
- Related IOCs from threat feeds
- YARA rule for the hash
- Sigma rules for network IOCs
- Recommended blocking actions

### 6.3 Vulnerability Triage

**Prompt**:
```
Triage CVE-2024-XXXXX for our environment:
- Affected products and versions
- Exploitation status
- Available patches
- Public PoC availability
- Risk rating
```

**Expected Output**:
- Detailed CVE analysis
- Patch availability and links
- Exploitation likelihood assessment
- Risk rating with justification
- Remediation recommendations

### 6.4 Threat Actor Research

**Prompt**:
```
Research the threat actor "APT-XX":
- Known TTPs
- Associated malware
- Recent campaigns
- IOCs
- MITRE ATT&CK mapping
```

**Expected Output**:
- Threat actor profile
- TTP summary with ATT&CK IDs
- Malware families used
- Recent campaign summaries
- IOC list for detection

---

## Phase 7: Implementation Timeline

Each phase includes **acceptance criteria** - the phase is complete when all criteria pass.

### Week 1: Foundation & Testing Infrastructure

**Tasks**:
- [ ] Clone claude-code-hooks-mastery repository
- [ ] Set up directory structure (simplified per Section 1.3)
- [ ] Configure API keys via keyring (NVD, CISA KEV)
- [ ] Set up pytest, ruff, mypy (see Phase 0)
- [ ] Implement basic NVD client with error handling
- [ ] Write unit tests for NVD client

**Acceptance Criteria**:
```bash
# All must pass to complete Week 1
uv run pytest tests/unit/test_nvd_client.py -v  # ≥5 tests pass
uv run ruff check src/                           # No errors
uv run mypy src/                                 # No errors
uv run python -c "from osint_agent.clients import NVDClient; print(NVDClient().lookup('CVE-2024-0001'))"  # Returns valid response
osint keys list                                  # NVD_API_KEY: configured
```

### Week 2: Core Hooks & Caching

**Tasks**:
- [ ] Implement ThreatContextCache class
- [ ] Implement SessionStart hook (non-blocking, cache-first)
- [ ] Implement IOC extraction patterns with validation
- [ ] Implement PostToolUse hook
- [ ] Write unit tests for IOC patterns (including false positive tests)
- [ ] Create SQLite schema for iocs.db with indexes

**Acceptance Criteria**:
```bash
# IOC extraction tests
uv run pytest tests/unit/test_ioc_extraction.py -v  # ≥15 tests pass (incl. false positives)

# Session start latency
time uv run hooks/session_start.py  # <2 seconds (with cold cache)
time uv run hooks/session_start.py  # <0.5 seconds (with warm cache)

# Database schema
sqlite3 data/iocs.db ".schema" | grep -q "CREATE INDEX"  # Indexes exist
```

### Week 3: Domain Validation & Rate Limiting

**Tasks**:
- [ ] Create `config/allowed_domains.json` with all OSINT sources
- [ ] Implement PreToolUse hook with configurable allowlist
- [ ] Implement per-domain rate limiting
- [ ] Add blocked request audit logging
- [ ] Integrate CISA KEV client
- [ ] Write integration tests with mocked HTTP responses

**Acceptance Criteria**:
```bash
# Rate limiting works
uv run pytest tests/unit/test_rate_limiting.py -v  # Rate limit enforcement tests pass

# Domain validation
uv run python -c "
from hooks.pre_tool_use import on_pre_tool_use
assert on_pre_tool_use('WebFetch', {'url': 'https://evil.com'})['blocked'] == True
assert on_pre_tool_use('WebFetch', {'url': 'https://nvd.nist.gov/x'})['blocked'] == False
print('Domain validation: PASS')
"

# Audit log created
test -f data/logs/blocked_requests.jsonl && echo "Audit log: PASS"
```

### Week 4: Threat Intelligence Integration

**Tasks**:
- [ ] Implement AlienVault OTX client
- [ ] Implement Abuse.ch clients (URLhaus, MalwareBazaar, ThreatFox)
- [ ] Implement multi-source IOC enrichment
- [ ] Add source reliability weighting
- [ ] Create `config/source_reliability.json`
- [ ] Write integration tests with VCR-recorded responses

**Acceptance Criteria**:
```bash
# API clients work
uv run pytest tests/integration/test_threat_intel.py -v --vcr-record=none  # Uses recorded cassettes

# Multi-source enrichment
uv run python -c "
from osint_agent.workflows import enrich_ioc
result = enrich_ioc('8.8.8.8', sources=['otx', 'abuseipdb'])
assert 'reputation_score' in result
assert len(result.get('sources', [])) >= 2
print('Multi-source enrichment: PASS')
"
```

### Week 5: Quality Gates & Workflows

**Tasks**:
- [ ] Implement pre-execution quality gate
- [ ] Implement post-execution quality gate
- [ ] Create CVE analysis workflow (10-step sequence)
- [ ] Create IOC enrichment workflow
- [ ] Implement confidence calibration
- [ ] Write end-to-end workflow tests

**Acceptance Criteria**:
```bash
# Quality gates enforce thresholds
uv run pytest tests/unit/test_quality_gates.py -v  # ≥10 tests pass

# CVE analysis workflow
uv run python -c "
from osint_agent.workflows import analyze_cve
result = analyze_cve('CVE-2024-0001')
assert result['confidence'] >= 0.6
assert len(result.get('sources', [])) >= 2
assert 'intelligence_gaps' in result
print('CVE workflow: PASS')
"

# End-to-end test
uv run pytest tests/e2e/test_daily_brief.py -v --vcr-record=none
```

### Week 6: Alerts, Backup & Polish

**Tasks**:
- [ ] Implement Notification hook with desktop alerts
- [ ] Create report templates (threat brief, CVE report)
- [ ] Implement daily threat brief workflow
- [ ] Set up automated backup script
- [ ] Add pre-commit hooks
- [ ] Documentation review and cleanup

**Acceptance Criteria**:
```bash
# Notification works
uv run python -c "
from hooks.notification import on_notification
on_notification('Test critical alert with CVSS 10', 'critical')
"  # Desktop notification appears

# Backup works
./scripts/backup.sh && ls backups/$(date +%Y-%m-%d)/iocs.db  # Backup created

# Pre-commit passes
pre-commit run --all-files  # All hooks pass

# Full test suite
uv run pytest --cov=osint_agent --cov-fail-under=70  # ≥70% coverage
```

### Ongoing Enhancements (Backlog)
- [ ] Build MCP server for dedicated tools
- [ ] Add Shodan integration
- [ ] Implement YARA/Sigma rule generation
- [ ] Add pattern/TTP correlation
- [ ] Implement campaign tracking
- [ ] Expand watchlist management with CPE matching
- [ ] Add MITRE ATT&CK mapping
- [ ] Proxy support for anonymity

---

## Appendix A: Configuration Files

### A.1 Watchlist Configuration

**File**: `data/watchlist.json`

```json
{
  "vendors": [
    "Microsoft",
    "Cisco",
    "Fortinet",
    "Palo Alto Networks",
    "VMware"
  ],
  "products": [
    "Windows Server",
    "Exchange Server",
    "FortiGate",
    "PAN-OS",
    "vCenter Server"
  ],
  "cpe_patterns": [
    "cpe:2.3:o:microsoft:windows_server:*",
    "cpe:2.3:a:cisco:ios_xe:*"
  ],
  "keywords": [
    "remote code execution",
    "authentication bypass",
    "privilege escalation"
  ]
}
```

### A.2 Claude Code Settings

**File**: `~/.claude/settings.json` (partial)

```json
{
  "hooks": {
    "session_start": [
      {
        "command": "uv run hooks/session_start.py",
        "timeout": 30000
      }
    ],
    "pre_tool_use": [
      {
        "command": "uv run hooks/pre_tool_use.py",
        "timeout": 5000
      }
    ],
    "post_tool_use": [
      {
        "command": "uv run hooks/post_tool_use.py",
        "timeout": 10000
      }
    ],
    "notification": [
      {
        "command": "uv run hooks/notification.py",
        "timeout": 5000
      }
    ]
  }
}
```

---

## Appendix B: Security & Operations

### B.1 API Key Security
- **Use system keychain** (see Section 4.5) instead of plaintext files
- Never commit keys to version control (add `*.env`, `api_keys.*` to `.gitignore`)
- Rotate keys quarterly or after suspected exposure
- Use read-only API scopes where available
- Monitor API usage dashboards for anomalies

### B.2 Data Handling
- IOC databases may contain sensitive information
- Encrypt at rest if storing locally (consider SQLCipher for iocs.db)
- Be cautious sharing extracted IOCs externally
- Follow your organization's data handling policies
- **Retention policy**: Auto-purge IOCs older than 90 days (configurable)

### B.3 Rate Limiting
- Respect API rate limits to avoid bans
- Implement exponential backoff on failures (see PreToolUse hook)
- Cache responses with appropriate TTL (1h for CVEs, 24h for static feeds)
- Consider paid tiers for heavy usage

### B.4 Network Security
- All OSINT queries should use HTTPS (enforced in allowed_domains.json)
- Consider using a VPN for research activities
- Optional proxy support for anonymity:
  ```python
  # config/proxy.json
  {
    "enabled": false,
    "http_proxy": "socks5://127.0.0.1:9050",
    "https_proxy": "socks5://127.0.0.1:9050",
    "exclude_domains": ["nvd.nist.gov", "cisa.gov"]
  }
  ```
- Be aware of logging by OSINT providers
- Some IOC lookups may trigger alerts

### B.5 Backup & Recovery Strategy

**Critical data to back up**:
| Data | Location | Backup Frequency | Method |
|------|----------|-----------------|--------|
| IOC Database | `data/iocs.db` | Daily | SQLite `.backup` command |
| Strategic Context | `data/context/strategic.json` | On change | Git-tracked |
| Operational Context | `data/context/operational.json` | On change | Git-tracked |
| Configuration | `config/*.json` | On change | Git-tracked |
| Extraction Logs | `data/logs/*.jsonl` | Weekly | Archive + rotate |

**Automated Backup Script**:
```bash
#!/bin/bash
# scripts/backup.sh - Run daily via cron

BACKUP_DIR="backups/$(date +%Y-%m-%d)"
mkdir -p "$BACKUP_DIR"

# SQLite backup (safe during writes)
sqlite3 data/iocs.db ".backup '$BACKUP_DIR/iocs.db'"

# Compress logs older than 7 days
find data/logs -name "*.jsonl" -mtime +7 -exec gzip {} \;

# Archive old backups (keep 30 days)
find backups -type d -mtime +30 -exec rm -rf {} \;

echo "Backup completed: $BACKUP_DIR"
```

**Recovery Procedure**:
```bash
# Restore IOC database from backup
cp backups/2024-01-15/iocs.db data/iocs.db

# Verify integrity
sqlite3 data/iocs.db "PRAGMA integrity_check;"

# Rebuild indexes if needed
sqlite3 data/iocs.db "REINDEX;"
```

**Git-Tracked Context Files**:
```gitignore
# .gitignore - Track context but not cache/sensitive data
data/cache/
data/logs/*.jsonl
data/context/tactical.json  # Session-specific, don't track
backups/
*.env
```

```bash
# Commit context changes after significant updates
git add data/context/strategic.json data/context/operational.json
git commit -m "Update threat context: new campaign tracking"
```

---

## Appendix C: Resources

### Documentation
- [Claude Code Hooks Documentation](https://docs.anthropic.com/en/docs/claude-code/hooks)
- [NVD API Documentation](https://nvd.nist.gov/developers)
- [AlienVault OTX API](https://otx.alienvault.com/api)
- [Abuse.ch API Documentation](https://urlhaus.abuse.ch/api/)

### Related Projects
- [claude-code-hooks-mastery](https://github.com/disler/claude-code-hooks-mastery) - Foundation repository
- [TSUKUYOMI](https://github.com/savannah-i-g/TSUKUYOMI) - Intelligence analysis framework (methodology reference)
- [MITRE ATT&CK](https://attack.mitre.org/) - Threat framework
- [YARA](https://virustotal.github.io/yara/) - Malware detection rules
- [Sigma](https://github.com/SigmaHQ/sigma) - Detection rule format

---

## Appendix D: TSUKUYOMI Module Templates

### D.1 CVE Analysis Module Definition

**File**: `modules/cve_analysis.json`

```json
{
  "module_id": "cve_analysis",
  "version": "1.0.0",
  "type": "intelligence_analysis",
  "title": "CVE Analysis and Triage",
  "description": "Systematic analysis of CVE vulnerabilities with enrichment and risk assessment",
  "dependencies": ["data_ingestion"],
  "capabilities_required": [
    "analytical_reasoning",
    "information_synthesis",
    "risk_assessment"
  ],
  "input_schema": {
    "cve_id": {
      "type": "string",
      "pattern": "^CVE-\\d{4}-\\d{4,}$",
      "required": true,
      "description": "CVE identifier to analyze"
    },
    "environment_context": {
      "type": "object",
      "required": false,
      "description": "Target environment details for risk contextualization"
    },
    "enrichment_sources": {
      "type": "array",
      "default": ["nvd", "cisa_kev", "vendor_advisories"],
      "description": "Sources to query for enrichment"
    }
  },
  "output_schema": {
    "cve_details": {
      "type": "object",
      "properties": {
        "id": "string",
        "description": "string",
        "cvss_v3": "object",
        "cwe_id": "string",
        "affected_products": "array",
        "references": "array"
      }
    },
    "exploitation_status": {
      "type": "object",
      "properties": {
        "in_kev": "boolean",
        "known_exploited": "boolean",
        "poc_available": "boolean",
        "exploit_maturity": "string"
      }
    },
    "risk_assessment": {
      "type": "object",
      "properties": {
        "base_risk": "string",
        "contextual_risk": "string",
        "priority": "string",
        "confidence": "number"
      }
    },
    "remediation": {
      "type": "object",
      "properties": {
        "patches_available": "boolean",
        "patch_links": "array",
        "workarounds": "array",
        "compensating_controls": "array"
      }
    },
    "intelligence_gaps": "array",
    "source_attribution": "array"
  },
  "execution_sequence": [
    {
      "step": 1,
      "name": "disclaimer_issuance",
      "description": "Issue analysis limitations and scope boundaries",
      "output_marker": "//DISCLAIMER"
    },
    {
      "step": 2,
      "name": "input_validation",
      "description": "Validate CVE ID format and check existence",
      "quality_gate": "pre_execution"
    },
    {
      "step": 3,
      "name": "primary_collection",
      "description": "Query NVD API for base CVE details",
      "sources": ["nvd"],
      "output_marker": "//RESULT"
    },
    {
      "step": 4,
      "name": "kev_crossreference",
      "description": "Check CISA KEV for active exploitation",
      "sources": ["cisa_kev"],
      "output_marker": "//CRITICAL (if exploited)"
    },
    {
      "step": 5,
      "name": "vendor_enrichment",
      "description": "Fetch vendor advisories and patch information",
      "sources": ["vendor_advisories", "security_blogs"],
      "output_marker": "//RESULT"
    },
    {
      "step": 6,
      "name": "poc_search",
      "description": "Search for public proof-of-concept code",
      "sources": ["github", "exploit_db"],
      "output_marker": "//ANOMALY (if found)"
    },
    {
      "step": 7,
      "name": "entity_extraction",
      "description": "Extract affected products, versions, CPEs",
      "quality_gate": "during_execution"
    },
    {
      "step": 8,
      "name": "pattern_correlation",
      "description": "Link to known campaigns, threat actors, malware",
      "output_marker": "//QUERY (if gaps found)"
    },
    {
      "step": 9,
      "name": "risk_synthesis",
      "description": "Combine all sources, calculate risk score",
      "output_marker": "//CONFIDENCE"
    },
    {
      "step": 10,
      "name": "report_generation",
      "description": "Produce structured analysis report",
      "quality_gate": "post_execution",
      "output_marker": "//RESULT"
    }
  ],
  "output_markers": ["//RESULT", "//DISCLAIMER", "//CRITICAL", "//ANOMALY", "//QUERY", "//CONFIDENCE", "//SOURCE"]
}
```

### D.2 IOC Enrichment Module Definition

**File**: `modules/ioc_enrichment.json`

```json
{
  "module_id": "ioc_enrichment",
  "version": "1.0.0",
  "type": "intelligence_collection",
  "title": "IOC Enrichment and Correlation",
  "description": "Multi-source enrichment of indicators of compromise with relationship mapping",
  "dependencies": ["data_ingestion", "entity_extraction"],
  "input_schema": {
    "iocs": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "value": "string",
          "type": "string (ipv4|ipv6|domain|url|md5|sha1|sha256|email)"
        }
      },
      "required": true
    },
    "sources": {
      "type": "array",
      "default": ["virustotal", "otx", "abuseipdb", "urlhaus"],
      "description": "Reputation sources to query"
    },
    "correlation_depth": {
      "type": "integer",
      "default": 1,
      "description": "Levels of related IOCs to retrieve (1-3)"
    }
  },
  "output_schema": {
    "enriched_iocs": {
      "type": "array",
      "items": {
        "ioc": "string",
        "type": "string",
        "reputation": {
          "score": "number (0-100)",
          "verdict": "string (clean|suspicious|malicious)",
          "confidence": "number"
        },
        "metadata": {
          "first_seen": "datetime",
          "last_seen": "datetime",
          "tags": "array",
          "threat_names": "array"
        },
        "source_results": "object",
        "related_iocs": "array"
      }
    },
    "correlation_graph": {
      "type": "object",
      "description": "Entity relationship map"
    },
    "threat_context": {
      "campaigns": "array",
      "threat_actors": "array",
      "malware_families": "array"
    }
  },
  "execution_sequence": [
    {"step": 1, "name": "input_validation", "description": "Validate IOC formats, deduplicate"},
    {"step": 2, "name": "type_detection", "description": "Auto-detect IOC types if not specified"},
    {"step": 3, "name": "parallel_queries", "description": "Query all reputation sources concurrently (max 5 concurrent)"},
    {"step": 4, "name": "result_normalization", "description": "Normalize scores to 0-100 scale"},
    {"step": 5, "name": "verdict_calculation", "description": "Calculate weighted consensus verdict"},
    {"step": 6, "name": "relationship_mapping", "description": "Extract related IOCs from source data"},
    {"step": 7, "name": "context_enrichment", "description": "Link to campaigns, actors, malware"},
    {"step": 8, "name": "confidence_calibration", "description": "Adjust confidence based on source agreement"},
    {"step": 9, "name": "gap_identification", "description": "Note missing data, suggest follow-ups"},
    {"step": 10, "name": "output_formatting", "description": "Structure results with source attribution"}
  ],
  "concurrency_config": {
    "max_parallel_requests": 5,
    "per_source_rate_limit": true,
    "timeout_per_source_seconds": 10,
    "retry_policy": {
      "max_retries": 2,
      "backoff_base_seconds": 1,
      "backoff_multiplier": 2
    }
  }
}
```

**Concurrency Implementation**:
```python
# src/osint_agent/enrichment.py
import asyncio
from asyncio import Semaphore
from typing import Optional

# Concurrency controls
MAX_CONCURRENT_REQUESTS = 5
PER_SOURCE_TIMEOUT = 10.0
MAX_RETRIES = 2
BACKOFF_BASE = 1.0


async def enrich_iocs_parallel(
    iocs: list[dict],
    sources: list[str],
    semaphore: Optional[Semaphore] = None
) -> list[dict]:
    """
    Enrich multiple IOCs across multiple sources with controlled concurrency.

    Args:
        iocs: List of {"value": "...", "type": "..."} dicts
        sources: List of source names to query
        semaphore: Optional semaphore for concurrency control

    Returns:
        List of enriched IOC results
    """
    if semaphore is None:
        semaphore = Semaphore(MAX_CONCURRENT_REQUESTS)

    async def enrich_single(ioc: dict) -> dict:
        """Enrich a single IOC across all sources."""
        results = {}

        async def query_source(source: str) -> tuple[str, dict]:
            async with semaphore:  # Limit concurrent requests
                for attempt in range(MAX_RETRIES + 1):
                    try:
                        client = get_client(source)
                        result = await asyncio.wait_for(
                            client.lookup_async(ioc["value"], ioc["type"]),
                            timeout=PER_SOURCE_TIMEOUT
                        )
                        return source, result
                    except asyncio.TimeoutError:
                        if attempt == MAX_RETRIES:
                            return source, {"error": "timeout"}
                    except Exception as e:
                        if attempt == MAX_RETRIES:
                            return source, {"error": str(e)}
                        # Exponential backoff
                        await asyncio.sleep(BACKOFF_BASE * (2 ** attempt))

        # Query all sources in parallel (bounded by semaphore)
        tasks = [query_source(s) for s in sources]
        source_results = await asyncio.gather(*tasks, return_exceptions=True)

        for source, result in source_results:
            if not isinstance(result, Exception):
                results[source] = result

        return {
            "ioc": ioc["value"],
            "type": ioc["type"],
            "source_results": results,
            "sources_queried": len(sources),
            "sources_succeeded": len([r for r in results.values() if "error" not in r]),
        }

    # Process all IOCs with bounded concurrency
    enriched = await asyncio.gather(*[enrich_single(ioc) for ioc in iocs])
    return list(enriched)
```
```

### D.3 Web Intelligence Collection Module Definition

**File**: `modules/webint_collection.json`

```json
{
  "module_id": "webint_collection",
  "version": "1.0.0",
  "type": "intelligence_collection",
  "title": "Web Intelligence Collection (WEBINT)",
  "description": "Systematic collection and filtering of open source intelligence from web sources",
  "dependencies": ["data_ingestion"],
  "discipline": "search_engine_intel",
  "input_schema": {
    "search_parameters": {
      "type": "object",
      "required": true,
      "properties": {
        "keywords": "array",
        "entities": "array",
        "date_range": "object"
      }
    },
    "source_prioritization": {
      "type": "object",
      "default": {
        "official_advisories": 1.0,
        "security_vendors": 0.9,
        "researcher_blogs": 0.7,
        "news_sites": 0.6,
        "social_media": 0.4
      }
    },
    "exclusion_criteria": {
      "type": "array",
      "description": "Domains or patterns to exclude"
    }
  },
  "output_schema": {
    "search_methodology": "string",
    "collected_intelligence": {
      "type": "array",
      "items": {
        "source_url": "string",
        "source_type": "string",
        "title": "string",
        "content_summary": "string",
        "extracted_entities": "array",
        "publication_date": "datetime",
        "reliability_rating": "string (A-F)",
        "credibility_rating": "string (1-6)"
      }
    },
    "source_assessment": {
      "total_sources": "integer",
      "by_reliability": "object",
      "potential_disinformation": "array"
    },
    "information_gaps": "array",
    "anomalous_findings": "array",
    "intelligence_synthesis": "string"
  },
  "execution_sequence": [
    {"step": 1, "name": "disclaimer_issuance", "description": "Issue limitations warning"},
    {"step": 2, "name": "search_strategy", "description": "Define queries, establish source hierarchy"},
    {"step": 3, "name": "primary_collection", "description": "Multi-engine searches, specialized databases"},
    {"step": 4, "name": "social_media_intel", "description": "Platform identification, profile collection"},
    {"step": 5, "name": "reliability_assessment", "description": "Credibility evaluation, disinformation detection"},
    {"step": 6, "name": "information_extraction", "description": "Data point extraction, metadata tagging"},
    {"step": 7, "name": "pattern_detection", "description": "Theme identification, contradiction flagging"},
    {"step": 8, "name": "intelligence_synthesis", "description": "Cross-stream integration, insight extraction"},
    {"step": 9, "name": "gap_analysis", "description": "Missing information identification"},
    {"step": 10, "name": "limitation_assessment", "description": "Technical constraint documentation"}
  ]
}
```

### D.4 Source Reliability Configuration

**File**: `config/source_reliability.json`

```json
{
  "reliability_codes": {
    "A": {
      "label": "Completely Reliable",
      "description": "Official government sources, established CERTs",
      "examples": ["CISA", "NVD", "MITRE", "US-CERT", "NCSC"],
      "weight": 1.0
    },
    "B": {
      "label": "Usually Reliable",
      "description": "Established security vendors and researchers",
      "examples": ["Microsoft", "Cisco Talos", "Mandiant", "CrowdStrike", "Recorded Future"],
      "weight": 0.85
    },
    "C": {
      "label": "Fairly Reliable",
      "description": "Reputable security blogs and independent researchers",
      "examples": ["Krebs on Security", "BleepingComputer", "The Record", "known researchers"],
      "weight": 0.7
    },
    "D": {
      "label": "Not Usually Reliable",
      "description": "Unverified social media, forums",
      "examples": ["Anonymous Twitter accounts", "Reddit posts", "Pastebin"],
      "weight": 0.4
    },
    "E": {
      "label": "Unreliable",
      "description": "Anonymous sources, known disinformation",
      "examples": ["Anonymous tips", "unverified leaks"],
      "weight": 0.1
    },
    "F": {
      "label": "Cannot Be Judged",
      "description": "New or unknown sources",
      "examples": ["First-time sources", "unclear provenance"],
      "weight": 0.3
    }
  },
  "credibility_codes": {
    "1": {
      "label": "Confirmed",
      "description": "Confirmed by multiple independent sources",
      "min_sources": 3
    },
    "2": {
      "label": "Probably True",
      "description": "Logical, consistent with known facts, from reliable source",
      "min_sources": 2
    },
    "3": {
      "label": "Possibly True",
      "description": "Reasonable but not confirmed",
      "min_sources": 1
    },
    "4": {
      "label": "Doubtful",
      "description": "Inconsistent or questionable details"
    },
    "5": {
      "label": "Improbable",
      "description": "Contradicts established facts"
    },
    "6": {
      "label": "Cannot Be Judged",
      "description": "Insufficient information to assess"
    }
  },
  "source_mappings": {
    "services.nvd.nist.gov": {"reliability": "A", "type": "official"},
    "cisa.gov": {"reliability": "A", "type": "official"},
    "cveawg.mitre.org": {"reliability": "A", "type": "official"},
    "msrc.microsoft.com": {"reliability": "B", "type": "vendor"},
    "sec.cloudapps.cisco.com": {"reliability": "B", "type": "vendor"},
    "www.virustotal.com": {"reliability": "B", "type": "aggregator"},
    "otx.alienvault.com": {"reliability": "B", "type": "threat_intel"},
    "urlhaus.abuse.ch": {"reliability": "B", "type": "threat_intel"},
    "bazaar.abuse.ch": {"reliability": "B", "type": "threat_intel"},
    "www.bleepingcomputer.com": {"reliability": "C", "type": "news"},
    "therecord.media": {"reliability": "C", "type": "news"},
    "krebsonsecurity.com": {"reliability": "C", "type": "blog"}
  }
}
```

### D.5 Entity Database Schema

**File**: `data/entities/schema.json`

```json
{
  "entity_types": {
    "person": {
      "fields": {
        "name": {"type": "string", "required": true},
        "aliases": {"type": "array"},
        "role": {"type": "string", "enum": ["threat_actor", "researcher", "vendor_contact", "official"]},
        "affiliation": {"type": "string"},
        "social_handles": {"type": "object"},
        "first_seen": {"type": "datetime"},
        "tags": {"type": "array"}
      }
    },
    "organization": {
      "fields": {
        "name": {"type": "string", "required": true},
        "aliases": {"type": "array"},
        "type": {"type": "string", "enum": ["apt_group", "criminal_group", "vendor", "agency", "cert"]},
        "country": {"type": "string"},
        "capabilities": {"type": "array"},
        "active": {"type": "boolean"},
        "mitre_id": {"type": "string"},
        "first_seen": {"type": "datetime"},
        "tags": {"type": "array"}
      }
    },
    "technical": {
      "fields": {
        "value": {"type": "string", "required": true},
        "type": {"type": "string", "required": true, "enum": ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "cve", "malware", "tool"]},
        "reputation_score": {"type": "number"},
        "verdict": {"type": "string", "enum": ["clean", "suspicious", "malicious", "unknown"]},
        "first_seen": {"type": "datetime"},
        "last_seen": {"type": "datetime"},
        "sources": {"type": "array"},
        "related_entities": {"type": "array"},
        "tags": {"type": "array"},
        "context": {"type": "object"}
      }
    },
    "pattern": {
      "fields": {
        "name": {"type": "string", "required": true},
        "type": {"type": "string", "enum": ["ttp", "campaign", "behavior", "communication", "financial"]},
        "description": {"type": "string"},
        "mitre_attack_ids": {"type": "array"},
        "indicators": {"type": "array"},
        "temporal_range": {"type": "object"},
        "associated_actors": {"type": "array"},
        "confidence": {"type": "number"},
        "tags": {"type": "array"}
      }
    }
  },
  "relationship_types": [
    "uses",
    "targets",
    "attributed_to",
    "related_to",
    "communicates_with",
    "hosted_on",
    "distributes",
    "exploits",
    "member_of",
    "variant_of"
  ]
}
```

---

## Appendix E: TSUKUYOMI-Enhanced Workflows

### E.1 Enhanced Daily Threat Brief Workflow

**Execution Sequence**:
```
1. //DISCLAIMER: Analysis limitations, temporal scope
2. //RESULT: CISA KEV additions (past 24h)
   - Source: A1 (CISA, confirmed)
3. //RESULT: Critical CVEs (CVSS 8.0+)
   - Source: A2 (NVD, probably true)
4. //CRITICAL: Watchlist matches
   - Immediate action required
5. //RESULT: Active campaigns from OTX
   - Source: B2 (AlienVault, probably true)
6. //ANOMALY: Unusual patterns detected
7. //QUERY: Gaps requiring follow-up
8. //CONFIDENCE: Overall assessment reliability
```

**Output Template**:
```markdown
# Daily Threat Intelligence Brief
**Date**: {{date}}
**Analyst**: OSINT Agent
**Classification**: UNCLASSIFIED

//DISCLAIMER
This brief is based on publicly available information. Findings should be
verified against internal telemetry before taking action.

## Executive Summary
{{executive_summary}}

## Critical Alerts (Immediate Action)
//CRITICAL
{{critical_items}}

## New Vulnerabilities
//RESULT
| CVE | CVSS | Products | KEV | Source Rating |
|-----|------|----------|-----|---------------|
{{cve_table}}

## Active Threats
//RESULT
{{active_threats}}

## Watchlist Matches
{{watchlist_matches}}

## Anomalies Detected
//ANOMALY
{{anomalies}}

## Intelligence Gaps
//QUERY
{{gaps}}

## Source Attribution
//SOURCE
{{sources}}

## Confidence Assessment
//CONFIDENCE
Overall Brief Reliability: {{confidence_rating}}
```

### E.2 Enhanced Incident Investigation Workflow

**Module Chain**: `data_ingestion` → `ioc_enrichment` → `pattern_correlation` → `threat_actor_attribution`

**Execution**:
```
Phase 1: IOC Ingestion
├── Validate IOC formats
├── Deduplicate entries
├── Assign entity IDs
└── Store in tactical context

Phase 2: Multi-Source Enrichment
├── Query VirusTotal (parallel)
├── Query AlienVault OTX (parallel)
├── Query AbuseIPDB (parallel)
├── Query URLhaus (parallel)
└── Normalize and merge results

Phase 3: Pattern Detection
├── Extract related IOCs
├── Identify common infrastructure
├── Map communication patterns
└── Detect TTP signatures

Phase 4: Attribution Analysis
├── Match against known actor profiles
├── Compare TTP fingerprints
├── Assess confidence levels
└── Document attribution gaps

Phase 5: Report Generation
├── Structure findings with markers
├── Include source ratings
├── Generate detection rules
└── Recommend response actions
```

---

*Document Version: 2.0*
*Created: 2026-01-23*
*Last Updated: 2026-01-23*

---

## Changelog

### v2.0 (2026-01-23) - Quality & Security Hardening
Based on Cerberus code review feedback, major improvements to production-readiness:

**Testing & Quality (Critical)**
- Added Phase 0: Testing & Quality Infrastructure
- Added pytest test examples for IOC extraction, API clients, workflows
- Added CI/CD configuration (.github/workflows/ci.yml)
- Added pre-commit hooks configuration
- Added acceptance criteria for each implementation phase

**Security Hardening (Critical)**
- Replaced plaintext .env with system keychain via `keyring` library
- Added CLI for secure key management (`osint keys set/list/delete`)
- Added proxy support configuration for research anonymity

**Performance Improvements (High)**
- Rewrote SessionStart hook to be non-blocking with cache-first strategy
- Added ThreatContextCache with TTL-based expiration
- Added background refresh for stale cache
- Added concurrency controls to IOC enrichment (max 5 parallel, per-source timeouts)

**Reliability Improvements (High)**
- Rewrote IOC extraction with validated patterns (TLD validation, defang support)
- Added timeout protection against ReDoS attacks
- Added structured JSON logging throughout
- Added try/catch with graceful degradation in all hooks
- Added SQLite indexes for IOC database

**Operations (High)**
- Simplified directory structure (consolidated config/, removed redundant dirs)
- Added backup & recovery strategy with automated scripts
- Added domain allowlist as configurable JSON (not hardcoded)
- Added blocked request audit logging
- Added quality gate implementation with concrete pass/fail thresholds

**Documentation**
- Added acceptance criteria to all timeline phases
- Added implementation code for all hook examples
- Expanded security considerations (B.5 Backup & Recovery)

### v1.2 (2026-01-23)
- Added TSUKUYOMI Framework Integration section
- Added modular JSON schema architecture
- Added structured output markers (//RESULT, //CRITICAL, //ANOMALY, etc.)
- Added five-tier context hierarchy
- Added entity extraction categories (Person, Org, Location, Technical, Pattern)
- Added intelligence discipline alignment
- Added multi-step execution sequences
- Added source assessment methodology (A-F, 1-6 ratings)
- Added quality assurance gates
- Added Appendix D: TSUKUYOMI Module Templates
- Added Appendix E: TSUKUYOMI-Enhanced Workflows
- Expanded directory structure to include modules, context, entities, templates
- Extended implementation timeline to 6 weeks

### v1.1 (2026-01-23)
- Added TSUKUYOMI as methodology reference

### v1.0 (2026-01-23)
- Initial proposal document
