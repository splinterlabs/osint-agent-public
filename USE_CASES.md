# OSINT Agent Use Cases

Six primary workflows for security research and threat intelligence.

---

## 1. Structured Investigation

Run a multi-source enrichment investigation on any indicator (IP, domain, hash, CVE, URL, email) with automated context isolation, coverage tracking, and verdict synthesis.

### Prompt Example
```
/investigate CVE-2026-24061
```

### What Happens
1. Indicator is classified by type
2. Investigation context is initialized (clean slate)
3. Each enrichment source is queried independently — console shows compact one-liners
4. Raw results are logged to a JSONL file for post-hoc analysis
5. A structured report is synthesized with verdict, confidence, risk level, and coverage table
6. Follow-up actions are offered (save report, generate rules, export STIX, run `/review`)

### MCP Tools Used
| Tool | Purpose |
|------|---------|
| `start_investigation` | Reset context, create investigation log |
| `lookup_cve` / `shodan_host_lookup` / etc. | Enrichment (varies by indicator type) |
| `lookup_ioc_otx` | OTX threat pulse lookup |
| `lookup_host_urlhaus` / `lookup_ioc_threatfox` | Abuse.ch checks |
| `attack_search_techniques` | MITRE ATT&CK mapping |
| `freshrss_search` | Threat feed mentions |
| `log_investigation_step` | Persist raw result to JSONL log |
| `log_investigation_conclusion` | Persist verdict and coverage |
| `add_finding` | Record significant findings in context |

### Expected Output
- Compact enrichment progress on console
- Structured report with verdict (Malicious/Suspicious/Benign/Inconclusive)
- Coverage table showing what was checked/skipped/errored
- JSONL log file with full raw API responses

---

## 2. Independent Review

Get a second-opinion judge layer on investigation findings. Runs a 16-check structured review across five categories.

### Prompt Example
```
/review
```

### What Happens
1. Findings are gathered from context, investigation log, or a report file
2. Evidence is re-examined independently (no carry-forward of prior conclusions)
3. 16 checks are evaluated: false positive analysis, logical consistency, confidence calibration, coverage gaps, analytical rigor
4. A verdict is assigned: CLOSE, INVESTIGATE MORE, or ESCALATE

### MCP Tools Used
| Tool | Purpose |
|------|---------|
| `get_findings` | Retrieve findings from current investigation |
| `get_active_iocs` | Retrieve IOCs from current investigation |
| `get_investigation_log` | Access raw enrichment data from JSONL log |

### Expected Output
- Checklist results table (PASS / FLAG / N/A for each check)
- Flags raised with explanations
- Verdict with specific next actions

---

## 3. Daily Threat Brief

Generate a daily summary of critical vulnerabilities and active threats.

### Prompt Example
```
/intel
```

### MCP Tools Used
| Tool | Purpose |
|------|---------|
| `get_critical_cves` | Fetch CVSS 8.0+ CVEs from last 24h |
| `get_kev_stats` | Check catalog status and recent additions |
| `search_kev_vendor` | Check KEV for watchlist vendors |
| `freshrss_get_unread` | Recent threat feed entries |

### Expected Output
- Summary of critical CVEs with affected products
- KEV additions with due dates
- Watchlist alerts with recommended actions
- Recent threat feed highlights

---

## 4. Incident Investigation

Investigate IOCs from SIEM alerts, find related indicators, and generate detection rules.

### Prompt Example
```
Investigate these IOCs from our SIEM alert:
- IP: 192.0.2.100
- Domain: malicious-example[.]com
- Hash: a1b2c3d4e5f6...

Check reputation, find related IOCs, and generate detection rules.
```

Or use the structured approach:
```
/investigate 192.0.2.100
```

### MCP Tools Used
| Tool | Purpose |
|------|---------|
| `extract_iocs_from_text` | Parse and validate IOCs from alert text |
| `shodan_host_lookup` | Host details, ports, services |
| `lookup_ioc_otx` | OTX pulse associations |
| `lookup_host_urlhaus` | URLhaus hosting history |
| `lookup_ioc_threatfox` | ThreatFox associations |
| `lookup_hash_malwarebazaar` | Malware sample details |
| `iocs_to_stix` | Convert to STIX bundle |
| `generate_yara_from_hashes` | YARA rule from file hashes |
| `generate_sigma_network` | Sigma rule for network IOCs |
| `generate_sigma_firewall` | Sigma rule for firewall logs |

### Expected Output
- Validated and defanged IOCs
- Reputation data from multiple sources
- STIX 2.1 bundle for threat intel platform import
- YARA and Sigma detection rules
- Campaign associations (if any)

---

## 5. Vulnerability Triage

Assess a specific CVE for your environment with exploitation context.

### Prompt Example
```
/cve CVE-2024-3400
```

### MCP Tools Used
| Tool | Purpose |
|------|---------|
| `lookup_cve` | Get CVE details with KEV status |
| `check_kev` | Detailed KEV entry if exploited |
| `search_kev_vendor` | Other vulns from same vendor |
| `shodan_vuln_lookup` | Internet-facing exposure count |
| `shodan_exploit_search` | Available public exploits |
| `attack_search_techniques` | Map to ATT&CK techniques |

### Expected Output
- CVSS score, vector, and severity
- Affected products (CPEs) and versions
- Active exploitation status from CISA KEV
- Internet-facing exposure data from Shodan
- MITRE ATT&CK technique mapping
- Required remediation actions and due dates

---

## 6. Threat Actor Research

Research a threat actor's TTPs, malware, and indicators using ATT&CK and campaign tracking.

### Prompt Example
```
Research the threat actor "APT29":
- Known TTPs
- Associated malware
- Recent campaigns
- IOCs for detection
```

### MCP Tools Used
| Tool | Purpose |
|------|---------|
| `attack_group_lookup` | ATT&CK group profile and aliases |
| `attack_software_lookup` | Malware/tools used by actor |
| `search_otx_pulses` | OTX pulses mentioning the actor |
| `extract_iocs_from_text` | Extract IOCs from threat reports |
| `campaign_create` | Track a new campaign |
| `campaign_add_ioc` / `campaign_add_ttp` | Associate IOCs and TTPs |
| `iocs_to_stix` | Export as STIX bundle |
| `generate_yara_from_hashes` | YARA rule from malware hashes |
| `generate_sigma_dns` | Sigma rule for C2 domain detection |

### Expected Output
- ATT&CK group profile with TTPs and associated software
- OTX intelligence pulses
- Campaign tracker with IOCs, TTPs, and CVEs
- STIX bundle for threat intel platform
- Detection rules (YARA, Sigma)

---

## Tool Quick Reference

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `lookup_cve` | CVE details + KEV status | `cve_id` |
| `get_critical_cves` | Recent high-severity CVEs | `cvss_min`, `days`, `max_results` |
| `check_kev` | Is CVE actively exploited? | `cve_id` |
| `search_kev_vendor` | KEV entries by vendor | `vendor` |
| `extract_iocs_from_text` | Extract IOCs from text | `content` |
| `iocs_to_stix` | Convert IOCs to STIX 2.1 | `iocs_json`, `labels` |
| `lookup_ioc_otx` | OTX reputation lookup | `indicator`, `indicator_type` |
| `shodan_host_lookup` | IP host details | `ip` |
| `shodan_dns_lookup` | Domain DNS records | `domain` |
| `shodan_vuln_lookup` | CVE exposure data | `cve_id` |
| `attack_technique_lookup` | ATT&CK technique details | `technique_id` |
| `attack_group_lookup` | Threat group profile | `group_id` |
| `attack_map_behavior` | Map behavior to techniques | `behavior` |
| `campaign_create` | Create campaign tracker | `name`, `description` |
| `generate_yara_from_hashes` | YARA rule from hashes | `rule_name`, `hashes_json` |
| `generate_sigma_network` | Sigma for network logs | `title`, `iocs_json` |

See [mcp-server/README.md](mcp-server/README.md) for the complete tool reference (60+ tools).
