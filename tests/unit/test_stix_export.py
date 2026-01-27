"""Unit tests for STIX export functionality."""

import json

import pytest

from osint_agent.stix_export import (
    STIXBundle,
    create_domain_observable,
    create_file_hash_observable,
    create_indicator,
    create_ipv4_observable,
    create_relationship,
    create_report,
    create_vulnerability,
    escape_stix_pattern_value,
    generate_stix_id,
    iocs_to_stix_bundle,
)


class TestEscapeSTIXPatternValue:
    """Tests for STIX pattern value escaping."""

    def test_escape_single_quote(self):
        result = escape_stix_pattern_value("test'value")
        assert result == "test\\'value"

    def test_escape_backslash(self):
        result = escape_stix_pattern_value("test\\value")
        assert result == "test\\\\value"

    def test_escape_both(self):
        result = escape_stix_pattern_value("test\\'value")
        assert result == "test\\\\\\'value"

    def test_no_escape_needed(self):
        result = escape_stix_pattern_value("normal-value.com")
        assert result == "normal-value.com"

    def test_url_with_special_chars(self):
        url = "http://evil.com/path?param='value'"
        result = escape_stix_pattern_value(url)
        assert "\\'" in result
        assert result == "http://evil.com/path?param=\\'value\\'"


class TestGenerateStixId:
    """Tests for deterministic STIX ID generation."""

    def test_same_input_same_id(self):
        id1 = generate_stix_id("ipv4-addr", "8.8.8.8")
        id2 = generate_stix_id("ipv4-addr", "8.8.8.8")
        assert id1 == id2

    def test_different_input_different_id(self):
        id1 = generate_stix_id("ipv4-addr", "8.8.8.8")
        id2 = generate_stix_id("ipv4-addr", "1.1.1.1")
        assert id1 != id2

    def test_id_format(self):
        stix_id = generate_stix_id("ipv4-addr", "8.8.8.8")
        assert stix_id.startswith("ipv4-addr--")
        # Should be valid UUID format after prefix
        uuid_part = stix_id.split("--")[1]
        assert len(uuid_part) == 36


class TestObservables:
    """Tests for STIX Cyber Observable creation."""

    def test_ipv4_observable(self):
        obs = create_ipv4_observable("8.8.8.8", labels=["malicious"])
        assert obs["type"] == "ipv4-addr"
        assert obs["value"] == "8.8.8.8"
        assert obs["spec_version"] == "2.1"
        assert "malicious" in obs["x_opencti_labels"]

    def test_domain_observable(self):
        obs = create_domain_observable("evil.com")
        assert obs["type"] == "domain-name"
        assert obs["value"] == "evil.com"

    def test_file_hash_md5(self):
        obs = create_file_hash_observable("a" * 32, "md5")
        assert obs["type"] == "file"
        assert "MD5" in obs["hashes"]
        assert obs["hashes"]["MD5"] == "a" * 32

    def test_file_hash_sha256(self):
        obs = create_file_hash_observable("b" * 64, "sha256")
        assert obs["type"] == "file"
        assert "SHA-256" in obs["hashes"]

    def test_file_hash_normalizes_type(self):
        obs = create_file_hash_observable("c" * 40, "sha-1")
        assert "SHA-1" in obs["hashes"]


class TestIndicator:
    """Tests for STIX Indicator creation."""

    def test_basic_indicator(self):
        indicator = create_indicator(
            pattern="[ipv4-addr:value = '8.8.8.8']",
            name="Test Indicator",
        )
        assert indicator["type"] == "indicator"
        assert indicator["pattern"] == "[ipv4-addr:value = '8.8.8.8']"
        assert indicator["pattern_type"] == "stix"
        assert indicator["name"] == "Test Indicator"

    def test_indicator_with_confidence(self):
        indicator = create_indicator(
            pattern="[domain-name:value = 'evil.com']",
            confidence=85,
        )
        assert indicator["confidence"] == 85

    def test_indicator_with_labels(self):
        indicator = create_indicator(
            pattern="[url:value = 'http://malware.com']",
            labels=["malicious", "c2"],
        )
        assert "malicious" in indicator["labels"]
        assert "c2" in indicator["labels"]


class TestVulnerability:
    """Tests for STIX Vulnerability creation."""

    def test_basic_vulnerability(self):
        vuln = create_vulnerability(
            cve_id="CVE-2024-1234",
            name="CVE-2024-1234",
            description="Test vulnerability",
            cvss_score=9.8,
        )
        assert vuln["type"] == "vulnerability"
        assert vuln["name"] == "CVE-2024-1234"
        assert vuln["x_opencti_cvss_base_score"] == 9.8

    def test_vulnerability_has_external_reference(self):
        vuln = create_vulnerability(
            cve_id="CVE-2024-1234",
            name="CVE-2024-1234",
            description="Test",
        )
        refs = vuln["external_references"]
        assert any(ref["source_name"] == "cve" for ref in refs)
        assert any("CVE-2024-1234" in ref.get("external_id", "") for ref in refs)


class TestReport:
    """Tests for STIX Report creation."""

    def test_basic_report(self):
        report = create_report(
            name="Daily Threat Brief",
            description="Summary of today's threats",
            report_types=["threat-report"],
        )
        assert report["type"] == "report"
        assert report["name"] == "Daily Threat Brief"
        assert "threat-report" in report["report_types"]

    def test_report_with_object_refs(self):
        indicator_id = "indicator--12345678-1234-1234-1234-123456789012"
        report = create_report(
            name="Test Report",
            description="Test",
            object_refs=[indicator_id],
        )
        assert indicator_id in report["object_refs"]


class TestRelationship:
    """Tests for STIX Relationship creation."""

    def test_basic_relationship(self):
        rel = create_relationship(
            source_ref="indicator--abc",
            target_ref="malware--xyz",
            relationship_type="indicates",
        )
        assert rel["type"] == "relationship"
        assert rel["relationship_type"] == "indicates"
        assert rel["source_ref"] == "indicator--abc"
        assert rel["target_ref"] == "malware--xyz"

    def test_relationship_with_confidence(self):
        rel = create_relationship(
            source_ref="threat-actor--abc",
            target_ref="malware--xyz",
            relationship_type="uses",
            confidence=75,
        )
        assert rel["confidence"] == 75


class TestSTIXBundle:
    """Tests for STIX Bundle builder."""

    def test_empty_bundle(self):
        bundle = STIXBundle()
        result = bundle.to_dict()
        assert result["type"] == "bundle"
        assert result["objects"] == []

    def test_add_objects(self):
        bundle = STIXBundle()
        obs = create_ipv4_observable("8.8.8.8")
        bundle.add(obs)
        assert len(bundle.objects) == 1

    def test_deduplication(self):
        bundle = STIXBundle()
        obs = create_ipv4_observable("8.8.8.8")
        bundle.add(obs)
        bundle.add(obs)  # Same object
        assert len(bundle.objects) == 1

    def test_to_json(self):
        bundle = STIXBundle()
        bundle.add(create_ipv4_observable("8.8.8.8"))
        json_str = bundle.to_json()
        parsed = json.loads(json_str)
        assert parsed["type"] == "bundle"
        assert len(parsed["objects"]) == 1


class TestIOCsToSTIXBundle:
    """Tests for bulk IOC conversion."""

    def test_convert_ipv4(self):
        iocs = {"ipv4": ["8.8.8.8", "1.1.1.1"]}
        bundle = iocs_to_stix_bundle(iocs)

        # Should have observables
        ipv4_obs = [o for o in bundle.objects if o["type"] == "ipv4-addr"]
        assert len(ipv4_obs) == 2

    def test_convert_with_indicators(self):
        iocs = {"ipv4": ["8.8.8.8"]}
        bundle = iocs_to_stix_bundle(iocs, create_indicators=True)

        indicators = [o for o in bundle.objects if o["type"] == "indicator"]
        assert len(indicators) >= 1

        # Should have relationship linking indicator to observable
        relationships = [o for o in bundle.objects if o["type"] == "relationship"]
        assert len(relationships) >= 1

    def test_convert_without_indicators(self):
        iocs = {"ipv4": ["8.8.8.8"]}
        bundle = iocs_to_stix_bundle(iocs, create_indicators=False)

        indicators = [o for o in bundle.objects if o["type"] == "indicator"]
        assert len(indicators) == 0

    def test_convert_mixed_iocs(self):
        iocs = {
            "ipv4": ["8.8.8.8"],
            "domain": ["evil.com"],
            "md5": ["a" * 32],
        }
        bundle = iocs_to_stix_bundle(iocs, labels=["malicious"])

        # Check all types present
        types = {o["type"] for o in bundle.objects}
        assert "ipv4-addr" in types
        assert "domain-name" in types
        assert "file" in types

    def test_labels_applied(self):
        iocs = {"domain": ["evil.com"]}
        bundle = iocs_to_stix_bundle(iocs, labels=["c2", "malware"])

        domain_obs = [o for o in bundle.objects if o["type"] == "domain-name"][0]
        assert "c2" in domain_obs["x_opencti_labels"]
        assert "malware" in domain_obs["x_opencti_labels"]

    def test_url_with_special_chars_escaped(self):
        """Verify URLs with special characters are properly escaped in patterns."""
        iocs = {"url": ["http://evil.com/path?q='test'"]}
        bundle = iocs_to_stix_bundle(iocs, create_indicators=True)

        indicators = [o for o in bundle.objects if o["type"] == "indicator"]
        assert len(indicators) == 1

        pattern = indicators[0]["pattern"]
        # Single quotes in URL should be escaped
        assert "\\'" in pattern
        # Pattern should be valid (no unescaped quotes breaking it)
        assert pattern.count("'") >= 2  # Opening and closing quotes

    def test_domain_with_special_chars_escaped(self):
        """Verify domains are escaped (edge case for IDN)."""
        iocs = {"domain": ["normal.com"]}
        bundle = iocs_to_stix_bundle(iocs, create_indicators=True)

        indicators = [o for o in bundle.objects if o["type"] == "indicator"]
        pattern = indicators[0]["pattern"]
        assert "[domain-name:value = 'normal.com']" == pattern
