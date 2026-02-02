"""Unit tests for IOC extraction."""


from osint_agent.extractors import (
    extract_iocs,
    refang,
    validate_domain,
    validate_hash,
    validate_ip,
)


class TestRefang:
    """Tests for defanged IOC refanging."""

    def test_refang_domain_brackets(self):
        assert refang("example[.]com") == "example.com"

    def test_refang_domain_dot_text(self):
        assert refang("example[dot]com") == "example.com"

    def test_refang_domain_parens(self):
        assert refang("example(.)com") == "example.com"

    def test_refang_url_hxxp(self):
        assert refang("hxxp://evil.com") == "http://evil.com"

    def test_refang_url_hxxps(self):
        assert refang("hxxps://evil.com") == "https://evil.com"

    def test_refang_email(self):
        assert refang("user[@]example[.]com") == "user@example.com"

    def test_refang_combined(self):
        assert refang("hxxps://malware[.]evil[.]com/path") == "https://malware.evil.com/path"


class TestValidateIP:
    """Tests for IP validation (filtering private/reserved)."""

    def test_valid_public_ip(self):
        assert validate_ip("8.8.8.8") is True
        assert validate_ip("1.1.1.1") is True
        assert validate_ip("203.0.113.50") is True

    def test_private_10_range(self):
        assert validate_ip("10.0.0.1") is False
        assert validate_ip("10.255.255.255") is False

    def test_private_172_range(self):
        assert validate_ip("172.16.0.1") is False
        assert validate_ip("172.31.255.255") is False
        assert validate_ip("172.15.0.1") is True  # Not in private range

    def test_private_192_range(self):
        assert validate_ip("192.168.0.1") is False
        assert validate_ip("192.168.255.255") is False

    def test_loopback(self):
        assert validate_ip("127.0.0.1") is False
        assert validate_ip("127.255.255.255") is False

    def test_link_local(self):
        assert validate_ip("169.254.0.1") is False

    def test_multicast_reserved(self):
        assert validate_ip("224.0.0.1") is False
        assert validate_ip("255.255.255.255") is False


class TestValidateDomain:
    """Tests for domain validation."""

    def test_valid_domains(self):
        assert validate_domain("google.com") is True
        assert validate_domain("sub.example.org") is True
        assert validate_domain("evil-site.net") is True

    def test_defanged_domain(self):
        assert validate_domain("malware[.]com") is True

    def test_invalid_tld(self):
        assert validate_domain("file.xyz123") is False
        assert validate_domain("test.invalid") is False

    def test_false_positive_domains(self):
        assert validate_domain("example.com") is False
        assert validate_domain("schema.org") is False
        assert validate_domain("w3.org") is False

    def test_version_string_rejection(self):
        assert validate_domain("1.0.0") is False
        assert validate_domain("v2.3.4") is False


class TestValidateHash:
    """Tests for hash validation."""

    def test_valid_hashes(self):
        # Use realistic hash patterns (not all-same-character)
        assert validate_hash("d8e8fca2dc0f896fd7cb4cb0031ba249", "md5") is True
        assert validate_hash("abc123def456abc123def456abc123def456abc123def456abc123def456abcd1234", "sha256") is True

    def test_all_zeros_rejected(self):
        assert validate_hash("0" * 32, "md5") is False
        assert validate_hash("0" * 64, "sha256") is False

    def test_all_same_char_rejected(self):
        assert validate_hash("a" * 64, "sha256") is False

    def test_empty_string_hash_rejected(self):
        # MD5 of empty string
        assert validate_hash("d41d8cd98f00b204e9800998ecf8427e", "md5") is False
        # SHA256 of empty string
        assert (
            validate_hash(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "sha256",
            )
            is False
        )


class TestExtractIOCs:
    """Tests for full IOC extraction."""

    def test_extract_ipv4(self):
        content = "Suspicious traffic from 8.8.8.8 and 1.1.1.1 detected"
        result = extract_iocs(content)
        assert "ipv4" in result
        assert "8.8.8.8" in result["ipv4"]
        assert "1.1.1.1" in result["ipv4"]

    def test_extract_ipv4_filters_private(self):
        content = "Internal: 192.168.1.1, External: 8.8.8.8"
        result = extract_iocs(content)
        assert "8.8.8.8" in result.get("ipv4", [])
        assert "192.168.1.1" not in result.get("ipv4", [])

    def test_extract_domain(self):
        content = "Malware beacon to evil.com and malware.net"
        result = extract_iocs(content)
        assert "domain" in result
        assert "evil.com" in result["domain"]
        assert "malware.net" in result["domain"]

    def test_extract_defanged_domain(self):
        content = "C2 server at evil[.]com"
        result = extract_iocs(content)
        assert "domain" in result
        assert "evil.com" in result["domain"]

    def test_extract_md5(self):
        content = "File hash: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        result = extract_iocs(content)
        assert "md5" in result
        assert "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" in result["md5"]

    def test_extract_sha256(self):
        hash_val = "a" * 63 + "b"  # 64 chars, not all same
        content = f"SHA256: {hash_val}"
        result = extract_iocs(content)
        assert "sha256" in result
        assert hash_val in result["sha256"]

    def test_extract_cve(self):
        content = "Exploit for CVE-2024-1234 and cve-2023-99999 available"
        result = extract_iocs(content)
        assert "cve" in result
        assert "CVE-2024-1234" in result["cve"]
        assert "CVE-2023-99999" in result["cve"]

    def test_extract_url(self):
        content = "Download from https://evil.com/malware.exe"
        result = extract_iocs(content)
        assert "url" in result
        assert "https://evil.com/malware.exe" in result["url"]

    def test_extract_defanged_url(self):
        content = "Payload at hxxps://evil[.]com/bad.exe"
        result = extract_iocs(content)
        assert "url" in result
        assert "https://evil.com/bad.exe" in result["url"]

    def test_no_false_positives_version_strings(self):
        content = "Version 1.2.3 released. Using library v4.5.6"
        result = extract_iocs(content)
        # Should not extract version strings as domains
        domains = result.get("domain", [])
        assert "1.2.3" not in str(domains)
        assert "4.5.6" not in str(domains)

    def test_deduplication(self):
        content = "IP 8.8.8.8 seen multiple times: 8.8.8.8, 8.8.8.8"
        result = extract_iocs(content)
        assert result["ipv4"].count("8.8.8.8") == 1

    def test_empty_content(self):
        result = extract_iocs("")
        assert result == {}

    def test_no_iocs(self):
        content = "This is just regular text with no indicators."
        result = extract_iocs(content)
        assert result == {}


class TestExtractIOCsTimeout:
    """Tests for timeout protection."""

    def test_large_content_truncated(self):
        # Content larger than MAX_CONTENT_LENGTH should be truncated
        large_content = "8.8.8.8 " * 100000
        result = extract_iocs(large_content)
        # Should still extract some IPs without hanging
        assert "ipv4" in result
