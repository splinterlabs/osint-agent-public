---
name: review
description: Independent judge layer for evaluating investigation findings
argument-hint: "[report-file]"
---

# Review Investigation Findings

Independently evaluate investigation findings as a second-opinion judge layer. This is designed to catch false positives, identify coverage gaps, and calibrate confidence.

## Arguments

- `$ARGUMENTS` - Optional: path to a report file (e.g., `reports/investigation_2026-01-27.md`). If omitted, reviews findings from the current conversation.

## Instructions

### Step 1: Gather Findings

Collect the findings to review from one of these sources (in priority order):

1. **File argument** — If `$ARGUMENTS` is a file path, read that file
2. **MCP context** — Use `get_findings` and `get_active_iocs` MCP tools to retrieve findings from the current investigation session
3. **Conversation context** — Use findings already present in the current conversation

If no findings are available from any source, inform the user and suggest running `/investigate` first.

### Step 2: Context Reset

**CRITICAL:** Evaluate the evidence independently. Do NOT carry forward the investigation's reasoning or conclusions. Re-examine each data point on its own merits as if seeing it for the first time. The purpose of this review is to provide an independent assessment, not to confirm the original analysis.

### Step 3: Structured Review Checklist

Work through all 16 checks across 5 categories. For each item, note PASS, FLAG, or N/A with a brief explanation.

#### A. False Positive Analysis

1. **Benign infrastructure** — Is this a known-good service (CDN, DNS resolver, cloud provider, sinkhole)? Check if the indicator belongs to Google, Cloudflare, Akamai, AWS, Azure, or similar.
2. **Sinkhole check** — Could this indicator be a sinkholed domain/IP operated by a security vendor or law enforcement?
3. **Common FP patterns** — Does this match known false positive patterns (e.g., localhost ranges, documentation IPs like 192.0.2.x, test domains)?
4. **Context decay** — Are the threat associations current, or are they stale (>90 days old)? Old associations with no recent activity may no longer be relevant.

#### B. Logical Consistency

5. **Cross-source agreement** — Do multiple independent sources agree on the assessment, or does only one source flag it?
6. **Attribution consistency** — If attributed to a threat actor or campaign, do the TTPs and infrastructure align with known reporting for that actor?
7. **Temporal consistency** — Do the timelines across sources make sense? Look for contradictions (e.g., attributed to a campaign that ended before the indicator was registered).

#### C. Confidence Calibration

8. **Single-source reliance** — Is the verdict based on a single source? Single-source findings should cap confidence at Medium.
9. **Source quality** — Are the sources authoritative? Distinguish between curated feeds (CISA KEV, MalwareBazaar) and community/open submissions (OTX pulses with low engagement).
10. **Circular reporting** — Could multiple sources be echoing the same original report rather than providing independent confirmation?

#### D. Coverage Gaps

11. **Unchecked sources** — Were any relevant enrichment sources skipped or errored? List them.
12. **Missing context** — Is there important context that was not gathered (e.g., WHOIS for domains, passive DNS for IPs, sandbox results for hashes)?
13. **Lateral indicators** — Were related indicators identified but not investigated (e.g., other IPs on the same C2, sibling domains, dropped files)?

#### E. Analytical Rigor

14. **Unstated assumptions** — Does the analysis rest on assumptions that aren't explicitly stated or validated?
15. **Alternative hypotheses** — Is there a plausible benign explanation that wasn't considered?
16. **Proportionality** — Does the severity assessment match the actual evidence, or is it over/under-stated?

### Step 4: Verdict

Based on the checklist, assign one of three verdicts:

#### CLOSE
The findings indicate benign activity or a false positive. Explain:
- Why the indicator is benign
- Which checklist items support this conclusion

#### INVESTIGATE MORE
The findings are incomplete or ambiguous. Provide:
- Specific gaps that need filling
- Exact tools or queries to run (e.g., "Run `shodan_host_lookup` on X" or "Check WHOIS for domain Y")
- What outcome would change the verdict

#### ESCALATE
The findings indicate a confirmed or high-confidence threat. Provide:
- **Priority:** P1 (active compromise) / P2 (confirmed threat, no active compromise) / P3 (low-confidence threat)
- **Concrete response actions:** block at firewall, isolate host, reset credentials, etc.
- **Detection recommendations:** specific Sigma/YARA rule suggestions

### Step 5: Present Review

```
## Review: [indicator or report name]

### Checklist Results

| # | Check                    | Result | Notes                        |
|---|--------------------------|--------|------------------------------|
| 1 | Benign infrastructure    | PASS   | Not a known CDN/cloud IP     |
| 2 | Sinkhole check           | PASS   | No sinkhole indicators       |
| 3 | Common FP patterns       | PASS   | Not in reserved ranges       |
| 4 | Context decay            | FLAG   | Oldest association is 2023   |
| ...                                                                    |

### Flags Raised
- [Summary of each FLAG with explanation]

### Verdict: [CLOSE | INVESTIGATE MORE | ESCALATE]
[Verdict details per Step 4]
```

### Step 6: Follow-ups

After presenting the review, offer:

1. Save review report to `reports/`
2. Run the specific enrichment steps identified in coverage gaps
3. Generate detection rules (YARA/Sigma) if verdict is ESCALATE
4. Export findings as STIX to `reports/`
5. Re-run `/investigate` on related indicators identified during review
