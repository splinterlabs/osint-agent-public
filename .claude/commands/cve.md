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

### Using the CLI

```bash
cd $PROJECT_ROOT && .venv/bin/python -m osint_agent.cli lookup "$ARGUMENTS" --format text
```

### Using MCP Tools (if available)

Use the NVD and CISA KEV MCP tools to fetch data.

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
4. Save full report to `reports/`

