# OSINT Agent Use Cases

Four primary workflows for security research and threat intelligence.

---

## 1. Daily Threat Brief

Generate a daily summary of critical vulnerabilities and active threats.

### Prompt Example
```
Generate a daily threat brief covering:
1. New critical vulnerabilities (CVSS 8.0+) from the past 24 hours
2. Any additions to CISA KEV
3. Highlight anything affecting my watchlist
```

### MCP Tools Used
| Tool | Purpose |
|------|---------|
| `get_critical_cves` | Fetch CVSS 8.0+ CVEs from last 24h |
| `get_kev_stats` | Check catalog status and recent additions |
| `search_kev_vendor` | Check KEV for watchlist vendors |

### Example Tool Calls
```
get_critical_cves cvss_min=8.0 days=1

get_kev_stats

search_kev_vendor Microsoft
search_kev_vendor Cisco
```

### Expected Output
- Summary of critical CVEs with affected products
- KEV additions with due dates
- Watchlist alerts with recommended actions

---

## 2. Incident Investigation

Investigate IOCs from SIEM alerts, find related indicators, and generate detection rules.

### Prompt Example
```
Investigate these IOCs from our SIEM alert:
- IP: 192.0.2.100
- Domain: malicious-example[.]com
- Hash: a1b2c3d4e5f6...

Check reputation, find related IOCs, and generate detection rules.
```

### MCP Tools Used
| Tool | Purpose |
|------|---------|
| `extract_iocs_from_text` | Parse and validate IOCs from alert text |
| `iocs_to_stix` | Convert to STIX bundle for correlation |
| `lookup_cve` | Check if IOCs relate to known CVEs |

### Example Tool Calls
```
extract_iocs_from_text "Source IP: 192.0.2.100 connected to malicious-example[.]com and dropped file with SHA256: a1b2c3..."

iocs_to_stix '{"ipv4": ["192.0.2.100"], "domain": ["malicious-example.com"]}' labels="incident-2024-001,siem-alert"
```

### Expected Output
- Validated and defanged IOCs
- STIX 2.1 bundle for threat intel platform import
- Related IOCs from threat feeds (requires OTX/Abuse.ch - Task #2, #3)
- Detection rules (requires rule generation - Task #7)

---

## 3. Vulnerability Triage

Assess a specific CVE for your environment with exploitation context.

### Prompt Example
```
Triage CVE-2024-3400 for our environment:
- Affected products and versions
- Exploitation status
- Available patches
- Risk rating
```

### MCP Tools Used
| Tool | Purpose |
|------|---------|
| `lookup_cve` | Get CVE details with KEV status |
| `check_kev` | Detailed KEV entry if exploited |
| `search_kev_vendor` | Other vulns from same vendor |

### Example Tool Calls
```
lookup_cve CVE-2024-3400

check_kev CVE-2024-3400

search_kev_vendor "Palo Alto"
```

### Expected Output
- CVSS score, vector, and severity
- Affected products (CPEs) and versions
- Active exploitation status from CISA KEV
- Required remediation actions and due dates
- Other KEV vulnerabilities from the same vendor

---

## 4. Threat Actor Research

Research a threat actor's TTPs, malware, and indicators.

### Prompt Example
```
Research the threat actor "APT-XX":
- Known TTPs
- Associated malware
- Recent campaigns
- IOCs for detection
```

### MCP Tools Used
| Tool | Purpose |
|------|---------|
| `extract_iocs_from_text` | Extract IOCs from threat reports |
| `iocs_to_stix` | Create STIX bundle with threat actor context |
| `search_kev_vendor` | Find exploited vulns used by actor |

### Example Tool Calls
```
# After gathering threat intel from reports
extract_iocs_from_text "<paste threat report text>"

iocs_to_stix '{"ipv4": [...], "domain": [...], "sha256": [...]}' labels="apt-xx,campaign-2024"
```

### Expected Output
- Extracted and validated IOCs
- STIX bundle for threat intel platform
- Related vulnerabilities exploited by actor
- Detection opportunities

---

## Tool Quick Reference

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `lookup_cve` | CVE details + KEV status | `cve_id` |
| `get_critical_cves` | Recent high-severity CVEs | `cvss_min`, `days`, `max_results` |
| `check_kev` | Is CVE actively exploited? | `cve_id` |
| `search_kev_vendor` | KEV entries by vendor | `vendor` |
| `get_kev_stats` | KEV catalog statistics | - |
| `extract_iocs_from_text` | Extract IOCs from text | `content` |
| `iocs_to_stix` | Convert IOCs to STIX 2.1 | `iocs_json`, `labels` |

---

## Planned Enhancements

These use cases will be enhanced when additional tools are implemented:

| Task | Enhancement |
|------|-------------|
| AlienVault OTX (#2) | Threat pulses, IOC reputation, related indicators |
| Abuse.ch (#3) | Malware samples, URLs, threat context |
| Rule Generation (#7) | YARA rules from hashes, Sigma rules from network IOCs |
| Context Management (#6) | Persistent investigation state across sessions |
