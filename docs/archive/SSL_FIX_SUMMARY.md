# SSL Certificate Fix Summary

**Date:** 2026-01-27
**Status:** ✓ RESOLVED

## Problem

Python SSL certificate verification was failing for all HTTPS connections with error:
```
[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate
```

## Root Cause

The project runs behind **Zscaler**, a corporate SSL inspection proxy that intercepts HTTPS traffic and re-signs certificates. Python's certifi package didn't include the necessary root and intermediate certificates to verify the Zscaler-signed certificate chain.

## Certificate Chain

The complete chain for Zscaler-intercepted connections:

```
Site Certificate (e.g., mb-api.abuse.ch)
  ↓ signed by
Gen Digital Inc. / zia.gendigital.com (Intermediate)
  ↓ signed by
NortonLifeLock Inc. Private SSL Inspection ICA (Intermediate)
  ↓ signed by
NortonLifeLock Inc. Private Root CA - GCS (Root)
  ↓ and also
Zscaler Root CA (Root)
```

## Solution Applied

Added the following certificates to the Python certifi CA bundle:

### 1. Zscaler Root CA
- **Source:** `~/Downloads/Zscaler Root CA.cer`
- **Format:** Converted from DER to PEM
- **Valid:** 2014-12-19 to 2042-05-06

### 2. NortonLifeLock Certificates
- **Source:** macOS System Keychain (`/Library/Keychains/System.keychain`)
- **Certificates:** Multiple intermediate and root certificates
- **Extracted:** Using `security find-certificate` command

### 3. Site Certificate Chain
- **Source:** Extracted from live SSL connection to `mb-api.abuse.ch`
- **Includes:** All intermediate certificates in the chain

## Implementation

Modified file: `src/osint_agent/clients/base.py`

### Changes Made

1. **Added certifi import:**
```python
import certifi
```

2. **Modified _request method to use certifi:**
```python
response = self.session.request(
    method=method,
    url=url,
    params=params,
    json=json_data,
    headers=headers,
    timeout=self.timeout,
    proxies=proxies,
    verify=certifi.where(),  # ← Added this line
    **kwargs,
)
```

3. **Updated certifi CA bundle:**
```bash
# Location
.venv/lib/python3.12/site-packages/certifi/cacert.pem

# Added certificates
cat /tmp/zscaler-root.pem >> certifi/cacert.pem
cat /tmp/all-certs.pem >> certifi/cacert.pem
cat /tmp/nortonlifelock-certs.pem >> certifi/cacert.pem
```

## Test Results

All 7 OSINT services successfully verify SSL certificates:

| Service              | SSL Verification | API Status        | Notes                              |
|----------------------|------------------|-------------------|------------------------------------|
| NVD                  | ✓ PASS           | Working           | SSL working correctly              |
| CISA KEV             | ✓ PASS           | Working           | SSL working correctly              |
| MITRE ATT&CK         | ✓ PASS           | ✓ SUCCESS         | Fully functional                   |
| AlienVault OTX       | ✓ PASS           | ✓ SUCCESS         | Fully functional                   |
| MalwareBazaar        | ✓ PASS           | ⚠ NO API ACCESS   | SSL works, 401 = no API keys       |
| ThreatFox            | ✓ PASS           | ⚠ NO API ACCESS   | SSL works, 401 = no API keys       |
| URLhaus              | ✓ PASS           | ⚠ NO API ACCESS   | SSL works, 401 = no API keys       |

**Result:** 7/7 services passed SSL verification (100%)

## Known Issues

### abuse.ch APIs Return 401 Unauthorized

**Services affected:**
- MalwareBazaar (`mb-api.abuse.ch`)
- ThreatFox (`threatfox-api.abuse.ch`)
- URLhaus (`urlhaus-api.abuse.ch`)

**Cause:** No API access configured. The `401 Unauthorized` errors indicate these services either:
1. Now require API keys/authentication (policy change)
2. Are restricted by corporate network policies

This is NOT an SSL verification issue - SSL works correctly.

**Evidence:**
- SSL verification succeeds (no certificate errors)
- Error code is `401` (authentication/authorization), not SSL-related
- No abuse.ch API keys configured in keymanager

**Potential Solutions:**
1. Check if abuse.ch now requires API keys and register for access
2. Verify corporate network policies allow access to `*.abuse.ch` APIs
3. Use alternative OSINT sources (OTX, VirusTotal, etc.) for similar data
4. Access abuse.ch web interfaces directly for manual lookups

## Maintenance

### When Certificates Expire or Change

If SSL errors reappear in the future, repeat the fix:

1. **Check for updated Zscaler certificate:**
   ```bash
   # Check Downloads folder
   ls ~/Downloads/*scaler*
   ```

2. **Extract from system keychain:**
   ```bash
   security find-certificate -c "Zscaler" -a -p /Library/Keychains/System.keychain > /tmp/zscaler.pem
   security find-certificate -c "NortonLifeLock" -a -p /Library/Keychains/System.keychain > /tmp/norton.pem
   ```

3. **Append to certifi bundle:**
   ```bash
   cat /tmp/zscaler.pem >> .venv/lib/python3.12/site-packages/certifi/cacert.pem
   cat /tmp/norton.pem >> .venv/lib/python3.12/site-packages/certifi/cacert.pem
   ```

4. **Verify:**
   ```bash
   .venv/bin/python3 -c "import certifi; print(certifi.where())"
   ```

### Automatic Certificate Update Script

Consider creating a setup script that automatically configures certificates when setting up the virtual environment.

## References

- **Certifi Documentation:** https://github.com/certifi/python-certifi
- **Python SSL Documentation:** https://docs.python.org/3/library/ssl.html
- **Zscaler SSL Inspection:** Corporate security policy documentation

## Files Modified

- `src/osint_agent/clients/base.py` - Added `verify=certifi.where()` to requests
- `.venv/lib/python3.12/site-packages/certifi/cacert.pem` - Added corporate certificates

## Verification Command

To verify SSL configuration is working:

```bash
.venv/bin/python3 << 'EOF'
import sys
sys.path.insert(0, 'src')
from osint_agent.clients.otx import OTXClient
from osint_agent.clients.attack import ATTACKClient

# Test OTX
otx = OTXClient()
result = otx.get_indicator("ipv4", "8.8.8.8", "general")
print(f"✓ OTX SSL verification successful")

# Test MITRE ATT&CK
attack = ATTACKClient()
result = attack.search_techniques("phishing", limit=1)
print(f"✓ MITRE ATT&CK SSL verification successful")

print("\nSSL configuration is working correctly!")
EOF
```

Expected output:
```
✓ OTX SSL verification successful
✓ MITRE ATT&CK SSL verification successful

SSL configuration is working correctly!
```

## Support

For issues with this fix:
1. Check certificate expiration dates
2. Verify certificates are still in system keychain
3. Contact IT for updated Zscaler certificates
4. Re-run the fix steps above
