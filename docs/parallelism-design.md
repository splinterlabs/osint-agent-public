# OSINT Agent Parallelism Design

**Date:** 2026-01-27
**Status:** Design Proposal

## Executive Summary

The OSINT agent is currently entirely synchronous, processing IOCs, CVE lookups, and threat intelligence queries sequentially. This analysis identifies **8 high-impact opportunities** for parallelism that could provide **5-50x speedups** in common workflows.

## Current Architecture Constraints

- **All synchronous code** - uses `requests` library (not async)
- **No connection pooling** - new connection per request
- **ThreadPoolExecutor** only used once (for timeout protection)
- **aiohttp in dependencies but unused** - ready for async migration
- **File locking** - campaigns use `filelock` with 10s timeout
- **Rate limiting** - handled per-client with exponential backoff

## High-Priority Parallelism Opportunities

### 1. Batch IOC Reputation Lookups (5-10x speedup)

**Current:** Sequential lookups in `freshrss_tools.py:165-182` and `campaign_tools.py:429`

```python
# Current: Sequential (SLOW)
for ioc in iocs:
    result = lookup_ioc_otx(ioc.type, ioc.value)
    results.append(result)
```

**Proposed:** Parallel batch processing

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def batch_lookup_iocs(iocs, max_workers=10):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(lookup_ioc_otx, ioc.type, ioc.value): ioc
            for ioc in iocs
        }
        for future in as_completed(futures):
            yield future.result()
```

**Impact:** 50 IOCs take 50s → 5-10s
**Risk:** Low - IOC lookups are independent
**Constraint:** Respect per-source rate limits

---

### 2. Multi-Vendor CVE Searches (3-10x speedup)

**Current:** Daily threat brief calls vendors sequentially

```python
# Current workflow
cves = get_critical_cves()
ms_vulns = search_kev_vendor("Microsoft")
cisco_vulns = search_kev_vendor("Cisco")
adobe_vulns = search_kev_vendor("Adobe")
```

**Proposed:** Parallel vendor queries

```python
def search_multiple_vendors(vendors, max_workers=5):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(search_kev_vendor, vendor): vendor
            for vendor in vendors
        }
        return {vendor: future.result() for future, vendor in futures.items()}

# Usage
vendors = ["Microsoft", "Cisco", "Adobe", "Apple", "Google"]
results = search_multiple_vendors(vendors)
```

**Impact:** 5 vendors @ 2s each = 10s → 2s
**Risk:** Low - CISA KEV catalog is static data
**Constraint:** API rate limits (usually generous)

---

### 3. Campaign Correlation Analysis (10-50x speedup)

**Current:** `campaign_tools.py:427-434` - sequential IOC correlation

```python
# Current: 50 IOCs x 100ms = 5 seconds
for ioc in campaign.iocs[:50]:
    related = find_by_ioc(ioc.ioc_type, ioc.value)
    for rel in related:
        if rel.id != campaign_id:
            related_campaign_ids.add(rel.id)
```

**Proposed:** Parallel correlation with result aggregation

```python
def correlate_campaign_parallel(campaign_id, iocs, max_workers=20):
    related_ids = set()
    lock = threading.Lock()

    def correlate_one(ioc):
        related = find_by_ioc(ioc.ioc_type, ioc.value)
        with lock:
            for rel in related:
                if rel.id != campaign_id:
                    related_ids.add(rel.id)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(correlate_one, iocs[:50])

    return related_ids
```

**Impact:** 50 IOCs @ 100ms = 5s → 250ms
**Risk:** Medium - requires thread-safe aggregation
**Constraint:** Campaign index is read-only (safe for parallel reads)

---

### 4. FreshRSS Feed Entry IOC Extraction (5-10x speedup)

**Current:** `freshrss_tools.py:165-182` - sequential entry processing

```python
# Current: 50 entries x 200ms = 10 seconds
for entry in result["entries"]:
    content = f"{entry.get('title', '')}\n{entry.get('summary', '')}"
    iocs = extract_iocs(content)
    if any(iocs.values()):
        entries_with_iocs.append(...)
```

**Proposed:** Parallel entry processing

```python
def extract_iocs_parallel(entries, max_workers=10):
    def process_entry(entry):
        content = f"{entry.get('title', '')}\n{entry.get('summary', '')}"
        iocs = extract_iocs(content)
        if any(iocs.values()):
            return {
                "entry": entry,
                "iocs": iocs,
                "feed_title": entry.get("origin", {}).get("title", "Unknown")
            }
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(process_entry, entries)

    return [r for r in results if r is not None]
```

**Impact:** 50 entries @ 200ms = 10s → 1-2s
**Risk:** Low - IOC extraction is CPU-bound, thread-safe
**Constraint:** Regex execution may contend for GIL

---

### 5. Infrastructure Pattern Analysis (5x speedup)

**Current:** `correlation.py:369-386` - sequential pattern matching

**Proposed:** Parallel pattern detection across IOC types

```python
def find_infrastructure_patterns_parallel(campaign_iocs):
    patterns = {}

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(find_ip_ranges, campaign_iocs): "ip_clusters",
            executor.submit(find_domain_patterns, campaign_iocs): "domain_patterns",
            executor.submit(find_asn_clusters, campaign_iocs): "asn_clusters",
            executor.submit(find_hosting_providers, campaign_iocs): "hosting_providers"
        }

        for future, pattern_type in futures.items():
            patterns[pattern_type] = future.result()

    return patterns
```

**Impact:** 4 analyses @ 500ms = 2s → 500ms
**Risk:** Low - pattern matching is read-only
**Constraint:** None

---

## Implementation Phases

### Phase 1: Thread Pool Parallelism (1-2 weeks)

**Goals:**
- Add `ThreadPoolExecutor` for IOC batch operations
- Implement parallel vendor CVE searches
- Add concurrent feed entry processing

**Changes:**
1. Create `src/osint_agent/parallel.py` - reusable parallel utilities
2. Update `freshrss_tools.py` - parallel IOC extraction
3. Update `campaign_tools.py` - parallel correlation
4. Add configuration for worker pool sizes

**Risk:** Low - thread pools are well-understood
**Testing:** Existing tests should pass + add concurrency tests

---

### Phase 2: Rate-Aware Batching (2-3 weeks)

**Goals:**
- Implement per-source rate limit tracking
- Add intelligent request batching
- Connection pooling for HTTP clients

**Changes:**
1. Update `BaseClient` with connection pool (requests.Session)
2. Add rate limiter state tracking per client
3. Implement batch queue with backpressure
4. Add metrics for parallel performance

**Risk:** Medium - rate limiting interaction
**Testing:** Mock API responses with rate limits

---

### Phase 3: Async/Await Migration (4-6 weeks)

**Goals:**
- Migrate to async I/O for all API clients
- Enable concurrent MCP tool execution
- Improve throughput for high-load scenarios

**Changes:**
1. Replace `requests` with `httpx` (async support)
2. Convert all client methods to `async def`
3. Update MCP tool handlers to async
4. Refactor campaign/context managers for async file I/O

**Risk:** High - major architectural change
**Testing:** Full regression suite + async integration tests

---

## Configuration Design

Add to `config/settings.json`:

```json
{
  "parallelism": {
    "enabled": true,
    "ioc_lookup_workers": 10,
    "campaign_correlation_workers": 20,
    "feed_processing_workers": 10,
    "vendor_search_workers": 5,
    "max_concurrent_requests": 50,
    "rate_limit_buffer": 0.8
  }
}
```

---

## Monitoring & Observability

Add metrics for parallel operations:

```python
# src/osint_agent/metrics.py
@dataclass
class ParallelMetrics:
    operation: str
    workers: int
    tasks_submitted: int
    tasks_completed: int
    tasks_failed: int
    total_time_seconds: float
    speedup_factor: float  # sequential_time / parallel_time
```

---

## Safety Considerations

### Thread Safety
- Campaign index: **Read-safe** (immutable reads, locked writes)
- Context manager: **Write-safe** (atomic file replacement)
- Correlation engine: **Read-only** (no shared state)

### Rate Limiting
- Respect per-source limits even with parallelism
- Add semaphore-based throttling per client
- Monitor 429 responses and adjust worker counts

### Error Handling
- Failed tasks don't crash entire batch
- Return partial results with error details
- Log all exceptions with context

---

## Performance Expectations

| Operation | Current | Phase 1 | Phase 2 | Phase 3 |
|-----------|---------|---------|---------|---------|
| 50 IOC lookups | 50s | 5-10s | 5-8s | 3-5s |
| 5 vendor searches | 10s | 2s | 2s | 1s |
| Campaign correlation (50 IOCs) | 5s | 250ms | 250ms | 100ms |
| 50 feed entries | 10s | 1-2s | 1-2s | 500ms |
| Daily threat brief | 60s | 15s | 12s | 8s |

**Total expected improvement: 4-7x faster for typical workflows**

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Rate limit violations | API bans | Per-client semaphore limiting |
| Thread contention | Degraded performance | Tune worker pool sizes |
| Filelock timeout | Tool failures | Increase timeout, add retry logic |
| Memory usage spike | OOM crashes | Limit max concurrent tasks |
| Debugging difficulty | Slower development | Add comprehensive logging |

---

## Next Steps

1. **Review this design** with stakeholders
2. **Create proof-of-concept** for IOC batch lookups (Phase 1)
3. **Benchmark** current vs parallel performance
4. **Implement Phase 1** with full test coverage
5. **Monitor production** metrics before Phase 2

