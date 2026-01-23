---
name: cve
description: Look up CVE details from NVD and CISA KEV
argument-hint: "<CVE-ID>"
---

# CVE Lookup

Look up detailed information about a CVE (Common Vulnerabilities and Exposures).

## Arguments

- `$ARGUMENTS` - CVE ID (e.g., CVE-2024-3400) - **required**

## Instructions

If no CVE ID is provided, ask the user for one.

### Data Sources

1. **NVD (National Vulnerability Database)** - Primary source for CVE details
2. **CISA KEV** - Check if CVE is in Known Exploited Vulnerabilities catalog
3. **Web Search** - For additional context, PoCs, and threat intelligence

### Using the CLI

```bash
cd $PROJECT_ROOT && python -m osint_agent.cli lookup "$ARGUMENTS" --format text
```

### Using MCP Tools (if available)

Use the NVD and CISA KEV MCP tools to fetch data.

### Fallback to Web Search

If API calls fail, use WebSearch to find:
- `"$ARGUMENTS" site:nvd.nist.gov`
- `"$ARGUMENTS" site:cisa.gov`
- `"$ARGUMENTS" vulnerability details`

## Output Format

Present CVE information in this structure:

```
## $ARGUMENTS - [Short Title]

### Severity
- **CVSS Score:** X.X (Critical/High/Medium/Low)
- **Vector:** [Attack vector details]
- **In CISA KEV:** Yes/No

### Affected Products
- Vendor: Product (versions)

### Description
[Full description]

### Exploitation
- Actively exploited: Yes/No
- PoC available: Yes/No
- [Any known threat actor activity]

### Remediation
- Patch available: Yes/No
- [Patch/mitigation details]

### References
- [NVD Link]
- [Vendor Advisory]
- [Other relevant links]
```

### Additional Actions

After displaying CVE info, offer to:
1. Add affected vendor/product to watchlist
2. Search for related IOCs
3. Generate YARA/Sigma rules if applicable

## Examples

- `/cve CVE-2024-3400` - Look up PAN-OS vulnerability
- `/cve CVE-2024-21887` - Look up Ivanti vulnerability
- `/cve CVE-2023-44487` - Look up HTTP/2 Rapid Reset
