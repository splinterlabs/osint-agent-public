---
name: investigate
description: Structured indicator investigation with enrichment and context isolation
argument-hint: "<indicator>"
---

# Investigate Indicator

Run a structured investigation against an indicator of compromise (IP, domain, hash, CVE, URL, or email).

## Arguments

- `$ARGUMENTS` - The indicator to investigate (e.g., `8.8.8.8`, `evil.com`, `CVE-2024-3400`, a SHA256 hash) - **required**

If no indicator is provided, ask the user for one.

## Instructions

### Step 1: Classify Indicator

Determine the indicator type from its format:

| Pattern | Type |
|---------|------|
| `x.x.x.x` or valid IPv4/IPv6 | **IP** |
| Hostname without scheme | **Domain** |
| 32 hex chars | **MD5 hash** |
| 40 hex chars | **SHA1 hash** |
| 64 hex chars | **SHA256 hash** |
| `CVE-YYYY-NNNNN` | **CVE** |
| Starts with `http://` or `https://` | **URL** |
| Contains `@` with domain | **Email** |

If ambiguous, ask the user to clarify.

### Step 2: Initialize Investigation

Use the `start_investigation` MCP tool to reset tactical context for a clean investigation. Pass the indicator value and classified type.

### Step 3: Run Enrichment Steps

**CRITICAL — Context Isolation:** Each enrichment step queries ONLY the original indicator `$ARGUMENTS`. Do NOT feed accumulated findings from one step into queries for another. This prevents false correlation chains.

Run the steps for the classified type. After each step, record results using the `add_finding` MCP tool with source name, verdict, and key details.

#### IP Address

1. `iocs search` — Check local IOC database:
   ```bash
   cd $PROJECT_ROOT && .venv/bin/python -m osint_agent.cli iocs search "$ARGUMENTS" --format text
   ```
2. `shodan_host_lookup` — Host details, open ports, services, vulns
3. `lookup_ioc_otx` — OTX pulses (type: `ipv4`)
4. `lookup_host_urlhaus` — URLhaus hosting history
5. `lookup_ioc_threatfox` — ThreatFox associations
6. `freshrss_search` — Recent threat feed mentions

#### Domain

1. `iocs search` — Check local IOC database:
   ```bash
   cd $PROJECT_ROOT && .venv/bin/python -m osint_agent.cli iocs search "$ARGUMENTS" --format text
   ```
2. `shodan_dns_lookup` — DNS records and resolution
3. `lookup_ioc_otx` — OTX pulses (type: `domain`)
4. `lookup_host_urlhaus` — URLhaus hosting history
5. `lookup_ioc_threatfox` — ThreatFox associations
6. `freshrss_search` — Recent threat feed mentions

#### Hash (MD5, SHA1, SHA256)

1. `iocs search` — Check local IOC database:
   ```bash
   cd $PROJECT_ROOT && .venv/bin/python -m osint_agent.cli iocs search "$ARGUMENTS" --format text
   ```
2. `lookup_hash_malwarebazaar` — MalwareBazaar sample details
3. `lookup_ioc_threatfox` — ThreatFox associations
4. `lookup_ioc_otx` — OTX pulses (type: `md5`, `sha1`, or `sha256` as appropriate)

#### CVE

1. CLI lookup for NVD + KEV data:
   ```bash
   cd $PROJECT_ROOT && .venv/bin/python -m osint_agent.cli lookup "$ARGUMENTS" --format text
   ```
2. `check_kev` — CISA Known Exploited Vulnerabilities check
3. Check if affected vendor/product is on watchlist — read `config/watchlist.json`
4. `shodan_vuln_lookup` — Internet-facing exposure count
5. `lookup_ioc_otx` — OTX pulses (type: `cve`)
6. `attack_search_techniques` — Map to MITRE ATT&CK techniques
7. `freshrss_search` — Recent threat feed mentions

#### URL

1. `iocs search` — Check local IOC database:
   ```bash
   cd $PROJECT_ROOT && .venv/bin/python -m osint_agent.cli iocs search "$ARGUMENTS" --format text
   ```
2. Extract the domain from the URL
3. `lookup_url_urlhaus` — URLhaus URL check
4. `lookup_ioc_threatfox` — ThreatFox associations
5. Then run **Domain** steps 2-6 on the extracted domain

#### Email

1. `iocs search` — Check local IOC database:
   ```bash
   cd $PROJECT_ROOT && .venv/bin/python -m osint_agent.cli iocs search "$ARGUMENTS" --format text
   ```
2. Extract the domain from the email address
3. Run **Domain** steps 2-6 on the extracted domain

### Step 4: Coverage Tracker

Present a summary table of what was checked:

```
## Coverage

| Source            | Status  | Key Finding              |
|-------------------|---------|--------------------------|
| Local IOC DB      | Checked | No matches               |
| Shodan            | Checked | 3 open ports             |
| OTX               | Checked | 2 pulses                 |
| URLhaus           | Skipped | N/A for hash type        |
| ThreatFox         | Checked | Linked to Cobalt Strike  |
| Threat Feeds      | Checked | No recent mentions       |
```

Mark each source as **Checked**, **Skipped** (with reason), or **Error** (with brief error).

### Step 5: Synthesize Report

Present a structured report:

```
## Investigation Report: $ARGUMENTS

**Type:** [classified type]
**Verdict:** Malicious | Suspicious | Benign | Inconclusive
**Confidence:** High | Medium | Low
**Risk Level:** Critical | High | Medium | Low | Info

### Summary
[2-3 sentence synthesis of findings]

### Key Findings
- [Most significant finding]
- [Second finding]
- ...

### Coverage
[Coverage table from Step 4]

### Raw Details
[Collapsed or summarized per-source results]
```

**Verdict criteria:**
- **Malicious** — Multiple sources confirm malicious activity or known-bad indicator
- **Suspicious** — Some indicators of compromise but incomplete evidence
- **Benign** — Known-good infrastructure (e.g., Google DNS, Cloudflare) with no malicious associations
- **Inconclusive** — Insufficient data from available sources

### Step 6: Follow-ups

After presenting the report, offer:

1. Save report to `reports/`
2. Add indicator to local IOC database
3. Run `/review` to get an independent assessment of the findings
4. Generate detection rules (YARA/Sigma) if applicable
5. Export findings as STIX to `reports/`
6. Investigate related indicators found during enrichment

### Step 7: Usage Footnote

Call the `get_investigation_usage` MCP tool and display a compact footnote at the very end:

```
---
> usage: {total_tool_calls} tool calls | {total_api_requests} API requests | {total_api_errors} errors | investigation: {investigation_name}
```

Always display this as the last line of output.
