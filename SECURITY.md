# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in OSINT Agent, please report it by:

1. **Email:** Create an issue on GitHub with the "security" label
2. **Provide:** Detailed description, reproduction steps, and potential impact
3. **Timeline:** We aim to respond within 48 hours

## Security Audit History

### February 2026 - Apex Hunter Comprehensive Audit
**Status:** ✅ Complete - All critical/high severity issues remediated

**Findings:**
- 3 CRITICAL vulnerabilities identified and fixed
- 2 HIGH severity vulnerabilities identified and fixed
- 3 MEDIUM severity issues (2 fixed, 1 deferred)

**Details:** See `reports/apex_hunter_security_audit_2026-02-02.md`

**Remediation Branch:** `security/apex-hunter-remediation`

**Fixed Vulnerabilities:**
- ✅ CVE-OSINT-2026-001: Path Traversal in Investigation Logs (CVSS 8.6)
- ✅ CVE-OSINT-2026-002: Server-Side Request Forgery (CVSS 7.5)
- ✅ CVE-OSINT-2026-003: Insecure File Permissions (CVSS 6.5)
- ✅ CVE-OSINT-2026-004: Password Memory Exposure (CVSS 6.8)
- ✅ CVE-OSINT-2026-005: Resource Leak (CVSS 4.3)

## Security Best Practices

### For Users

**API Keys:**
- Store API keys in system keyring using `osint-agent keys set <KEY_NAME>`
- Never commit `.env` files or credentials to git
- Rotate API keys periodically

**File Permissions:**
After installation, verify sensitive files have correct permissions:
```bash
# Check context files
ls -l data/context/*.json
# Should show: -rw------- (600)

# Check campaign files
ls -l data/campaigns/*.json
# Should show: -rw------- (600)

# Check cache files
ls -l data/cache/api/*.json
# Should show: -rw------- (600)
```

If permissions are incorrect, fix them:
```bash
chmod 600 data/context/*.json
chmod 600 data/campaigns/*.json
chmod 600 data/cache/api/*.json
```

**Network Security:**
- The web fetch tools have SSRF protection built-in
- They will block attempts to access:
  - Private IP ranges (192.168.x.x, 10.x.x.x, 172.16.x.x)
  - Loopback addresses (127.0.0.1, localhost)
  - Cloud metadata services (169.254.169.254)

**Data Protection:**
- Investigation logs contain sensitive data - restrict access to `data/logs/`
- Campaign data contains threat intelligence - protect `data/campaigns/`
- Context files contain active IOCs - secure `data/context/`

### For Developers

**Code Security:**
- All file operations use atomic writes with secure permissions (0600)
- All SQL queries use parameterized statements
- All user input is validated before processing
- API credentials are never logged or exposed in errors
- SSRF protection is mandatory for all HTTP requests

**Testing Security Fixes:**
```bash
# Run security-focused tests
pytest tests/ -v -k security

# Check file permissions
make check-permissions

# Verify SSRF protection
pytest tests/test_web_fetch_security.py

# Verify path traversal protection
pytest tests/test_investigation_log_security.py
```

**Adding New Features:**
Before adding features that:
- Accept user input → Validate and sanitize
- Make HTTP requests → Use SSRF protection
- Write files → Use atomic writes with 0600 permissions
- Handle credentials → Minimize memory exposure, use keyring
- Process untrusted data → Implement timeout protection

**Pre-commit Checks:**
```bash
# Install pre-commit hooks
pre-commit install

# Run all security checks
make security-check
```

## Security Architecture

### Defense in Depth

**Layer 1: Input Validation**
- Path traversal detection (filename extraction, character blocking)
- SSRF protection (IP validation, blocklists)
- IOC extraction timeout (ReDoS prevention)

**Layer 2: Access Control**
- File permissions (0600 on all sensitive files)
- Keyring-based credential storage
- No world-readable data files

**Layer 3: Network Security**
- SSRF protection on all web fetches
- SSL/TLS by default
- Proxy support with bypass lists

**Layer 4: Data Protection**
- Atomic file writes prevent corruption
- Secure permissions prevent unauthorized access
- Minimal credential exposure (fetch on-demand, immediate cleanup)

**Layer 5: Audit & Logging**
- Security events logged (SSRF attempts, path traversal)
- Investigation logs for forensics
- Usage tracking for anomaly detection

### Threat Model

**In Scope:**
- Malicious MCP tool usage (path traversal, SSRF)
- Local user privilege escalation (file permission issues)
- Memory inspection attacks (credential exposure)
- Network-based attacks (SSRF, internal scanning)
- Resource exhaustion (DoS, memory/thread leaks)

**Out of Scope:**
- Physical access attacks
- Supply chain attacks (malicious dependencies)
- Social engineering
- Brute force attacks (no authentication layer in scope)

### Security Controls

| Control | Implementation | Status |
|---------|---------------|--------|
| Input Validation | Multi-layer path/URL validation | ✅ Active |
| SSRF Protection | IP-based blocking + blocklists | ✅ Active |
| File Permissions | 0600 on sensitive files | ✅ Active |
| Credential Storage | System keyring (OS-encrypted) | ✅ Active |
| SQL Injection | Parameterized queries | ✅ Active |
| ReDoS Protection | Timeout on regex operations | ✅ Active |
| Rate Limiting | MCP tool throttling | ⚠️ Planned |
| Encryption at Rest | Cache file encryption | ⚠️ Planned |

## Vulnerability Disclosure Timeline

We follow a responsible disclosure process:

1. **Day 0:** Vulnerability reported privately
2. **Day 1-2:** Acknowledgment sent to reporter
3. **Day 1-7:** Investigation and impact assessment
4. **Day 7-30:** Fix developed and tested
5. **Day 30-45:** Fix deployed, public disclosure
6. **Day 45+:** CVE assigned if applicable

## Security Updates

**Subscribe to security updates:**
- Watch this repository on GitHub
- Enable "Security alerts" notifications
- Check `SECURITY.md` periodically

**Applying security updates:**
```bash
# Update to latest version
git pull origin main
pip install -e . --upgrade

# Verify security fixes
make verify-security

# Review and fix file permissions
chmod 600 data/context/*.json
chmod 600 data/campaigns/*.json
chmod 600 data/cache/api/*.json
```

## Contact

**Security Team:** GitHub Issues with "security" label
**General Questions:** GitHub Discussions
**Emergency:** Create high-priority GitHub issue

---

**Last Updated:** 2026-02-02
**Next Review:** 2026-08-02 (6 months)
