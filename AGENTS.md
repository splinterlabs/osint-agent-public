# OSINT Agent - AI Agent Instructions

Instructions for AI agents (Claude Code, Cursor, Aider, etc.) working with this project.

## Report & Export Output

All generated reports, exports, and output files MUST be saved to the `reports/` directory. Never save generated files to the project root.

Use descriptive filenames with timestamps, for example:
- `reports/iocs_extraction_2026-01-26.json`
- `reports/iocs_extraction_2026-01-26.stix.json`
- `reports/cve-2024-3400_report_2026-01-26.md`
- `reports/intel_summary_2026-01-26.md`
- `reports/campaign_apt29_2026-01-26.stix.json`

This does NOT apply to data files (those go in `data/`) or detection rules (those go in `rules/`).
