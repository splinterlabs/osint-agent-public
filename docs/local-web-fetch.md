# Local Web Fetch Tools

## Overview

The local web fetch tools provide an alternative to the built-in `WebFetch` tool that may be blocked by network restrictions or enterprise security policies. These tools use the local `requests` library with **realistic browser headers** to blend in with normal web traffic.

## Why Use These Tools?

- **Network restrictions**: Corporate firewalls or proxies may block claude.ai from making web requests
- **Realistic headers**: Rotating User-Agents mimic real browsers (Chrome, Firefox, Safari)
- **SSL flexibility**: Option to disable SSL verification for internal/corporate networks
- **Better error handling**: Clear error messages for debugging connectivity issues

## Available Tools

### 1. `local_web_fetch`

Fetch HTML/text content from URLs with automatic text extraction.

```python
local_web_fetch(
    url="https://example.com",
    extract_text=True,      # Extract readable text (default: True)
    timeout=30,             # Request timeout in seconds (default: 30)
    verify_ssl=True         # SSL verification (default: True)
)
```

**Use cases:**
- Fetch security blog posts or advisories
- Extract text from threat intelligence reports
- Download HTML content for analysis

**Example:**
```python
# Fetch OpenWall oss-security disclosure
local_web_fetch("https://www.openwall.com/lists/oss-security/2026/01/20/2")

# Get raw HTML without text extraction
local_web_fetch("https://example.com", extract_text=False)

# Skip SSL verification for corporate networks
local_web_fetch("https://internal.corp.com", verify_ssl=False)
```

### 2. `local_web_fetch_json`

Fetch JSON data from APIs with automatic parsing and formatting.

```python
local_web_fetch_json(
    url="https://api.example.com/v1/data",
    timeout=30,             # Request timeout in seconds (default: 30)
    verify_ssl=True         # SSL verification (default: True)
)
```

**Use cases:**
- Query public threat intelligence APIs
- Fetch CVE data from NVD API
- Access JSON-based security feeds

**Example:**
```python
# Fetch CVE from NVD API
local_web_fetch_json("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-1234")

# Query threat feed API
local_web_fetch_json("https://api.threatintel.example/v1/indicators")
```

### 3. `local_web_fetch_raw`

Fetch binary content (images, PDFs, archives) with base64 encoding.

```python
local_web_fetch_raw(
    url="https://example.com/malware.bin",
    timeout=30,             # Request timeout in seconds (default: 30)
    verify_ssl=True         # SSL verification (default: True)
)
```

**Use cases:**
- Download malware samples (for analysis, not execution!)
- Fetch PDF security reports
- Retrieve binary indicators

**Example:**
```python
# Download PDF report
local_web_fetch_raw("https://example.com/report.pdf")

# Fetch binary file
local_web_fetch_raw("https://example.com/sample.bin")
```

## User-Agent Rotation

The tools automatically rotate between 12 realistic User-Agents:

- **Chrome** on Windows, macOS, Linux
- **Firefox** on Windows, macOS, Linux
- **Safari** on macOS
- **Edge** on Windows

Each request randomly selects a User-Agent to avoid detection as an automated tool.

## Headers Sent

All requests include realistic browser headers:

```
User-Agent: Mozilla/5.0 (rotating from pool)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Cache-Control: max-age=0
```

## SSL Verification

By default, SSL certificates are verified (`verify_ssl=True`). This ensures secure connections and prevents man-in-the-middle attacks.

**When to disable SSL verification:**
- Internal corporate networks with self-signed certificates
- Testing environments without proper SSL setup
- Proxied connections that intercept SSL

**Security warning:** Only disable SSL verification when absolutely necessary and when you trust the network.

## Error Handling

The tools provide clear error messages for common issues:

```
Error: Request timed out after 30 seconds
Error: Connection failed - [Errno 61] Connection refused
Error: HTTP 404 - Not Found
Error: HTTP 403 - Forbidden
```

## Comparison with Built-in WebFetch

| Feature | local_web_fetch | WebFetch (built-in) |
|---------|----------------|---------------------|
| Network restrictions | ✅ Works around | ❌ May be blocked |
| Realistic headers | ✅ Rotating User-Agents | ❓ Unknown |
| SSL flexibility | ✅ Configurable | ❌ No control |
| Binary files | ✅ Base64 encoding | ❓ Limited |
| JSON parsing | ✅ Automatic | ❓ Manual |

## Best Practices

1. **Use built-in WebFetch first**: Try the built-in tool before falling back to local fetch
2. **Keep SSL verification enabled**: Only disable for trusted internal networks
3. **Respect rate limits**: Don't abuse rotating User-Agents to bypass rate limiting
4. **Check robots.txt**: Respect site policies for automated access
5. **Use appropriate timeouts**: 30s is reasonable, adjust for slow connections

## Installation

The tools require `beautifulsoup4` for HTML parsing:

```bash
pip install "beautifulsoup4>=4.12,<5.0"
```

Or install MCP optional dependencies:

```bash
pip install -e ".[mcp]"
```

## Examples

### Investigate CVE disclosure

```python
# Try built-in WebFetch first
WebFetch("https://www.openwall.com/lists/oss-security/2026/01/20/2",
         "Extract CVE details and affected versions")

# If blocked, use local fetch
local_web_fetch("https://www.openwall.com/lists/oss-security/2026/01/20/2")
```

### Fetch threat intelligence

```python
# Query GreyNoise analysis
local_web_fetch("https://www.labs.greynoise.io/grimoire/2026-01-22-analysis/")

# Download STIX bundle
local_web_fetch_json("https://api.threatintel.example/stix/bundle.json")
```

### Check vendor advisory

```python
# Debian security advisory
local_web_fetch("https://lists.debian.org/debian-lts-announce/2026/01/msg00025.html")

# Microsoft Security Update Guide
local_web_fetch("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-1234")
```

## Troubleshooting

**"Connection failed" error:**
- Check internet connectivity
- Verify URL is correct and accessible
- Try with `verify_ssl=False` if on corporate network

**"Request timed out" error:**
- Increase timeout: `timeout=60`
- Check if site is slow or rate-limiting
- Try again later if site is experiencing issues

**"HTTP 403 Forbidden" error:**
- Site may block automated requests
- User-Agent rotation should help, but some sites are strict
- Consider manual browser access if blocked

**SSL certificate verification failed:**
- Common on corporate networks with SSL interception
- Use `verify_ssl=False` for trusted internal networks
- Install corporate CA certificate in system trust store

## Security Considerations

**Ethical use:**
- Only access public information for defensive security research
- Respect site terms of service
- Don't use for malicious purposes or unauthorized access

**Data privacy:**
- Be careful with URLs containing sensitive data
- Don't log or expose API keys in URLs
- Consider using POST requests for sensitive data (not implemented yet)

**Defense in depth:**
- Validate and sanitize fetched content before processing
- Be cautious with binary files (malware samples)
- Use sandboxing for untrusted content analysis
