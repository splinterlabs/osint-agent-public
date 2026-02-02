# OSINT Agent - Project Instructions

## Report & Export Output

All generated reports, exports, and output files MUST be saved to the `reports/` directory. Never save generated files to the project root.

Use descriptive filenames with timestamps, for example:
- `reports/iocs_extraction_2026-01-26.json`
- `reports/iocs_extraction_2026-01-26.stix.json`
- `reports/cve-2024-3400_report_2026-01-26.md`
- `reports/intel_summary_2026-01-26.md`
- `reports/campaign_apt29_2026-01-26.stix.json`

This does NOT apply to data files (those go in `data/`) or detection rules (those go in `rules/`).

## Report Formatting Standards

All markdown reports MUST include clickable reference links for CVEs and threat intelligence sources. This is a **CRITICAL** requirement.

### CVE Reference Links

Every CVE mentioned in a report MUST include a hyperlink:

```markdown
# NVD links (primary source):
See [NVD CVE-YYYY-NNNNN](https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN) for details

# CISA KEV links (for actively exploited):
See [CISA KEV CVE-YYYY-NNNNN](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for details
```

### URL Templates

| Source | Template |
|--------|----------|
| NVD CVE | `https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN` |
| CISA KEV | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` |
| MITRE ATT&CK Technique | `https://attack.mitre.org/techniques/TNNNN/` |
| MITRE ATT&CK Group | `https://attack.mitre.org/groups/GNNNN/` |

### Template Reference

Use `config/templates/intel_report_template.md` as the canonical format for all threat intelligence reports.

**NEVER** write placeholder text like "(Check NVD for details)" without a hyperlink. Every reference must be clickable.
