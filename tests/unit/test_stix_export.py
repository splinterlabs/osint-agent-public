"""Unit tests for STIX 2.1 export."""

import json

from osint_agent.stix_export import (
    STIXBundle,
    create_domain_observable,
    create_email_observable,
    create_file_hash_observable,
    create_indicator,
    create_ipv4_observable,
    create_ipv6_observable,
    create_malware,
    create_relationship,
    create_report,
    create_threat_actor,
    create_url_observable,
    create_vulnerability,
    cve_to_stix,
    escape_stix_pattern_value,
    generate_stix_id,
    iocs_to_stix_bundle,
    now_iso,
)


class TestGenerateStixId:
    """Tests for deterministic STIX ID generation."""

    def test_deterministic(self):
        id1 = generate_stix_id("ipv4-addr", "1.2.3.4")
        id2 = generate_stix_id("ipv4-addr", "1.2.3.4")
        assert id1 == id2

    def test_different_inputs_different_ids(self):
        id1 = generate_stix_id("ipv4-addr", "1.2.3.4")
        id2 = generate_stix_id("ipv4-addr", "5.6.7.8")
        assert id1 != id2

    def test_different_types_different_ids(self):
        id1 = generate_stix_id("ipv4-addr", "value")
        id2 = generate_stix_id("domain-name", "value")
        assert id1 != id2

    def test_id_format(self):
        stix_id = generate_stix_id("indicator", "test")
        assert stix_id.startswith("indicator--")
        uuid_part = stix_id.split("--")[1]
        parts = uuid_part.split("-")
        assert len(parts) == 5


class TestEscapeStixPatternValue:
    """Tests for STIX pattern value escaping."""

    def test_escape_backslash(self):
        assert escape_stix_pattern_value("C:\\Windows") == "C:\\\\Windows"

    def test_escape_single_quote(self):
        assert escape_stix_pattern_value("it's") == "it\\'s"

    def test_escape_combined(self):
        assert escape_stix_pattern_value("C:\\it's") == "C:\\\\it\\'s"

    def test_no_escape_needed(self):
        assert escape_stix_pattern_value("1.2.3.4") == "1.2.3.4"

    def test_url_with_quotes(self):
        url = "http://evil.com/path?param='value'"
        result = escape_stix_pattern_value(url)
        assert "\\'" in result


class TestNowIso:
    """Tests for timestamp generation."""

    def test_format(self):
        ts = now_iso()
        assert ts.endswith(".000Z")
        assert "T" in ts
        assert len(ts) == 24  # YYYY-MM-DDTHH:MM:SS.000Z


class TestSTIXBundle:
    """Tests for STIX bundle builder."""

    def test_add_object(self):
        bundle = STIXBundle()
        obj = {"type": "ipv4-addr", "id": "ipv4-addr--test-1", "value": "1.2.3.4"}
        returned_id = bundle.add(obj)
        assert returned_id == "ipv4-addr--test-1"
        assert len(bundle.objects) == 1

    def test_deduplication(self):
        bundle = STIXBundle()
        obj = {"type": "ipv4-addr", "id": "ipv4-addr--test-1", "value": "1.2.3.4"}
        bundle.add(obj)
        bundle.add(obj)
        assert len(bundle.objects) == 1

    def test_different_objects_added(self):
        bundle = STIXBundle()
        bundle.add({"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "1.2.3.4"})
        bundle.add({"type": "ipv4-addr", "id": "ipv4-addr--2", "value": "5.6.7.8"})
        assert len(bundle.objects) == 2

    def test_to_dict(self):
        bundle = STIXBundle()
        bundle.add({"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "1.2.3.4"})
        result = bundle.to_dict()
        assert result["type"] == "bundle"
        assert result["id"].startswith("bundle--")
        assert len(result["objects"]) == 1

    def test_to_json(self):
        bundle = STIXBundle()
        bundle.add({"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "1.2.3.4"})
        json_str = bundle.to_json()
        parsed = json.loads(json_str)
        assert parsed["type"] == "bundle"

    def test_save(self, tmp_path):
        bundle = STIXBundle()
        bundle.add({"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "1.2.3.4"})
        path = tmp_path / "test_bundle.json"
        bundle.save(str(path))
        assert path.exists()
        parsed = json.loads(path.read_text())
        assert parsed["type"] == "bundle"
        assert len(parsed["objects"]) == 1

    def test_empty_bundle(self):
        bundle = STIXBundle()
        result = bundle.to_dict()
        assert result["objects"] == []


class TestSTIXObservables:
    """Tests for STIX Cyber Observable creation."""

    def test_create_ipv4(self):
        obs = create_ipv4_observable("1.2.3.4", labels=["malicious"])
        assert obs["type"] == "ipv4-addr"
        assert obs["value"] == "1.2.3.4"
        assert obs["spec_version"] == "2.1"
        assert obs["x_opencti_labels"] == ["malicious"]
        assert obs["id"].startswith("ipv4-addr--")

    def test_create_ipv4_no_labels(self):
        obs = create_ipv4_observable("1.2.3.4")
        assert obs["x_opencti_labels"] == []

    def test_create_ipv6(self):
        obs = create_ipv6_observable("::1")
        assert obs["type"] == "ipv6-addr"
        assert obs["value"] == "::1"
        assert obs["x_opencti_labels"] == []

    def test_create_domain(self):
        obs = create_domain_observable("evil.com")
        assert obs["type"] == "domain-name"
        assert obs["value"] == "evil.com"

    def test_create_url(self):
        obs = create_url_observable("https://evil.com/payload")
        assert obs["type"] == "url"
        assert obs["value"] == "https://evil.com/payload"

    def test_create_file_hash_md5(self):
        obs = create_file_hash_observable("a" * 32, "md5")
        assert obs["type"] == "file"
        assert obs["hashes"]["MD5"] == "a" * 32

    def test_create_file_hash_sha256(self):
        obs = create_file_hash_observable("b" * 64, "sha256")
        assert obs["hashes"]["SHA-256"] == "b" * 64

    def test_create_file_hash_sha1(self):
        obs = create_file_hash_observable("c" * 40, "sha1")
        assert obs["hashes"]["SHA-1"] == "c" * 40

    def test_create_file_hash_normalizes_type(self):
        obs = create_file_hash_observable("c" * 40, "sha-1")
        assert "SHA-1" in obs["hashes"]

    def test_create_email(self):
        obs = create_email_observable("attacker@evil.com")
        assert obs["type"] == "email-addr"
        assert obs["value"] == "attacker@evil.com"


class TestSTIXDomainObjects:
    """Tests for STIX Domain Object creation."""

    def test_create_vulnerability(self):
        vuln = create_vulnerability(
            cve_id="CVE-2024-1234",
            name="CVE-2024-1234",
            description="Test vulnerability",
            cvss_score=9.8,
        )
        assert vuln["type"] == "vulnerability"
        assert vuln["name"] == "CVE-2024-1234"
        assert vuln["description"] == "Test vulnerability"
        assert vuln["x_opencti_cvss_base_score"] == 9.8
        assert vuln["external_references"][0]["external_id"] == "CVE-2024-1234"
        assert "nvd.nist.gov" in vuln["external_references"][0]["url"]

    def test_create_vulnerability_no_cvss(self):
        vuln = create_vulnerability(
            cve_id="CVE-2024-5678",
            name="CVE-2024-5678",
            description="No score",
        )
        assert "x_opencti_cvss_base_score" not in vuln

    def test_create_vulnerability_extra_refs(self):
        vuln = create_vulnerability(
            cve_id="CVE-2024-1234",
            name="CVE-2024-1234",
            description="Test",
            external_references=[{"source_name": "vendor", "url": "https://vendor.com"}],
        )
        assert len(vuln["external_references"]) == 2

    def test_create_indicator(self):
        ind = create_indicator(
            pattern="[ipv4-addr:value = '1.2.3.4']",
            name="Malicious IP",
            description="Known C2",
            labels=["malicious-activity"],
            confidence=85,
        )
        assert ind["type"] == "indicator"
        assert ind["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
        assert ind["pattern_type"] == "stix"
        assert ind["name"] == "Malicious IP"
        assert ind["confidence"] == 85
        assert ind["labels"] == ["malicious-activity"]

    def test_create_indicator_minimal(self):
        ind = create_indicator(pattern="[ipv4-addr:value = '1.2.3.4']")
        assert "name" not in ind
        assert "description" not in ind
        assert "labels" not in ind
        assert "confidence" not in ind

    def test_create_report(self):
        report = create_report(
            name="Threat Report",
            description="Analysis of campaign",
            report_types=["threat-report"],
            object_refs=["indicator--abc"],
            labels=["campaign"],
            confidence=75,
        )
        assert report["type"] == "report"
        assert report["name"] == "Threat Report"
        assert report["report_types"] == ["threat-report"]
        assert "indicator--abc" in report["object_refs"]
        assert report["confidence"] == 75

    def test_create_report_defaults(self):
        report = create_report(name="Simple", description="Minimal")
        assert report["report_types"] == ["threat-report"]
        assert report["object_refs"] == []

    def test_create_threat_actor(self):
        actor = create_threat_actor(
            name="APT29",
            description="Russian threat actor",
            aliases=["Cozy Bear", "The Dukes"],
            threat_actor_types=["nation-state"],
        )
        assert actor["type"] == "threat-actor"
        assert actor["name"] == "APT29"
        assert actor["aliases"] == ["Cozy Bear", "The Dukes"]
        assert actor["threat_actor_types"] == ["nation-state"]

    def test_create_threat_actor_minimal(self):
        actor = create_threat_actor(name="Unknown")
        assert actor["name"] == "Unknown"
        assert "aliases" not in actor
        assert "description" not in actor

    def test_create_malware(self):
        mal = create_malware(
            name="Emotet",
            description="Banking trojan",
            malware_types=["trojan"],
            is_family=True,
        )
        assert mal["type"] == "malware"
        assert mal["name"] == "Emotet"
        assert mal["is_family"] is True
        assert mal["malware_types"] == ["trojan"]

    def test_create_malware_defaults(self):
        mal = create_malware(name="Unknown")
        assert mal["is_family"] is True
        assert "malware_types" not in mal


class TestSTIXRelationships:
    """Tests for STIX Relationship Object creation."""

    def test_create_relationship(self):
        rel = create_relationship(
            source_ref="indicator--abc",
            target_ref="malware--def",
            relationship_type="indicates",
            description="Indicator linked to malware",
            confidence=90,
        )
        assert rel["type"] == "relationship"
        assert rel["relationship_type"] == "indicates"
        assert rel["source_ref"] == "indicator--abc"
        assert rel["target_ref"] == "malware--def"
        assert rel["confidence"] == 90

    def test_deterministic_relationship_id(self):
        rel1 = create_relationship("a--1", "b--2", "indicates")
        rel2 = create_relationship("a--1", "b--2", "indicates")
        assert rel1["id"] == rel2["id"]

    def test_different_relationships_different_ids(self):
        rel1 = create_relationship("a--1", "b--2", "indicates")
        rel2 = create_relationship("a--1", "b--2", "uses")
        assert rel1["id"] != rel2["id"]

    def test_minimal_relationship(self):
        rel = create_relationship("a--1", "b--2", "related-to")
        assert "description" not in rel
        assert "confidence" not in rel


class TestIOCsToStixBundle:
    """Tests for IOC-to-STIX bundle conversion."""

    def test_ipv4_bundle(self):
        iocs = {"ipv4": ["1.2.3.4", "5.6.7.8"]}
        bundle = iocs_to_stix_bundle(iocs)
        result = bundle.to_dict()
        # 2 observables + 2 indicators + 2 relationships
        assert len(result["objects"]) == 6

    def test_ipv6_bundle(self):
        iocs = {"ipv6": ["::1"]}
        bundle = iocs_to_stix_bundle(iocs)
        result = bundle.to_dict()
        types = [obj["type"] for obj in result["objects"]]
        assert "ipv6-addr" in types
        assert "indicator" in types

    def test_domain_bundle(self):
        iocs = {"domain": ["evil.com"]}
        bundle = iocs_to_stix_bundle(iocs)
        result = bundle.to_dict()
        types = [obj["type"] for obj in result["objects"]]
        assert "domain-name" in types
        assert "indicator" in types
        assert "relationship" in types

    def test_url_bundle(self):
        iocs = {"url": ["https://evil.com/bad"]}
        bundle = iocs_to_stix_bundle(iocs)
        result = bundle.to_dict()
        types = [obj["type"] for obj in result["objects"]]
        assert "url" in types

    def test_hash_bundle(self):
        iocs = {"sha256": ["a" * 64]}
        bundle = iocs_to_stix_bundle(iocs)
        result = bundle.to_dict()
        file_objs = [o for o in result["objects"] if o["type"] == "file"]
        assert len(file_objs) == 1
        assert "SHA-256" in file_objs[0]["hashes"]

    def test_multiple_hash_types(self):
        iocs = {"md5": ["a" * 32], "sha1": ["b" * 40], "sha256": ["c" * 64]}
        bundle = iocs_to_stix_bundle(iocs)
        result = bundle.to_dict()
        file_objs = [o for o in result["objects"] if o["type"] == "file"]
        assert len(file_objs) == 3

    def test_email_no_indicator(self):
        iocs = {"email": ["attacker@evil.com"]}
        bundle = iocs_to_stix_bundle(iocs)
        result = bundle.to_dict()
        # Email only gets observable, no indicator
        assert len(result["objects"]) == 1
        assert result["objects"][0]["type"] == "email-addr"

    def test_labels_applied(self):
        iocs = {"ipv4": ["1.2.3.4"]}
        bundle = iocs_to_stix_bundle(iocs, labels=["malicious"])
        result = bundle.to_dict()
        obs = [o for o in result["objects"] if o["type"] == "ipv4-addr"][0]
        assert "malicious" in obs["x_opencti_labels"]

    def test_no_indicators_flag(self):
        iocs = {"ipv4": ["1.2.3.4"]}
        bundle = iocs_to_stix_bundle(iocs, create_indicators=False)
        result = bundle.to_dict()
        assert len(result["objects"]) == 1
        assert result["objects"][0]["type"] == "ipv4-addr"

    def test_empty_iocs(self):
        bundle = iocs_to_stix_bundle({})
        result = bundle.to_dict()
        assert result["objects"] == []

    def test_mixed_iocs(self):
        iocs = {
            "ipv4": ["1.2.3.4"],
            "domain": ["evil.com"],
            "sha256": ["a" * 64],
            "url": ["https://evil.com/bad"],
            "email": ["bad@evil.com"],
        }
        bundle = iocs_to_stix_bundle(iocs)
        result = bundle.to_dict()
        types = {obj["type"] for obj in result["objects"]}
        assert "ipv4-addr" in types
        assert "domain-name" in types
        assert "file" in types
        assert "url" in types
        assert "email-addr" in types
        assert "indicator" in types
        assert "relationship" in types

    def test_url_name_truncation(self):
        long_url = "https://evil.com/" + "a" * 100
        iocs = {"url": [long_url]}
        bundle = iocs_to_stix_bundle(iocs)
        result = bundle.to_dict()
        indicators = [o for o in result["objects"] if o["type"] == "indicator"]
        assert indicators[0]["name"].endswith("...")


class TestCveToStix:
    """Tests for CVE data to STIX conversion."""

    def test_basic_conversion(self):
        cve_data = {
            "id": "CVE-2024-1234",
            "description": "Test vulnerability",
            "cvss_v3_score": 9.8,
            "references": [
                {"url": "https://vendor.com/advisory", "source": "vendor"},
            ],
        }
        result = cve_to_stix(cve_data)
        assert result["type"] == "vulnerability"
        assert result["name"] == "CVE-2024-1234"
        assert result["description"] == "Test vulnerability"
        assert result["x_opencti_cvss_base_score"] == 9.8
        # NVD ref + vendor ref
        assert len(result["external_references"]) == 2

    def test_no_references(self):
        cve_data = {
            "id": "CVE-2024-5678",
            "description": "No refs",
            "references": [],
        }
        result = cve_to_stix(cve_data)
        assert len(result["external_references"]) == 1
        assert result["external_references"][0]["source_name"] == "cve"

    def test_missing_fields(self):
        cve_data = {}
        result = cve_to_stix(cve_data)
        assert result["type"] == "vulnerability"
        assert result["name"] == ""
        assert result["description"] == ""

    def test_no_cvss_score(self):
        cve_data = {
            "id": "CVE-2024-9999",
            "description": "Test",
            "cvss_v3_score": None,
            "references": [],
        }
        result = cve_to_stix(cve_data)
        assert "x_opencti_cvss_base_score" not in result
