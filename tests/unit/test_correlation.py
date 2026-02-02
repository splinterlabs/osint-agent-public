"""Unit tests for correlation engine."""

from datetime import UTC, datetime, timedelta

from osint_agent.correlation import (
    CorrelationEngine,
    CorrelationResult,
)


class TestCorrelationResult:
    """Tests for CorrelationResult dataclass."""

    def test_default_values(self):
        result = CorrelationResult(ioc_type="ipv4", ioc_value="192.0.2.1")

        assert result.ioc_type == "ipv4"
        assert result.ioc_value == "192.0.2.1"
        assert result.sources == []
        assert result.related_iocs == []
        assert result.campaigns == []
        assert result.techniques == []
        assert result.confidence == 0.0


class TestCorrelationEngine:
    """Tests for CorrelationEngine."""

    def test_index_ioc(self):
        engine = CorrelationEngine()
        engine.index_ioc(
            ioc_type="ipv4",
            value="192.0.2.1",
            source="intel_feed",
            timestamp="2024-01-01T00:00:00",
            metadata={"tags": ["c2"]},
        )

        assert "ipv4:192.0.2.1" in engine._ioc_index
        assert len(engine._ioc_index["ipv4:192.0.2.1"]) == 1
        assert engine._ioc_index["ipv4:192.0.2.1"][0]["source"] == "intel_feed"

    def test_index_multiple_sightings(self):
        engine = CorrelationEngine()
        engine.index_ioc("ipv4", "192.0.2.1", "source1")
        engine.index_ioc("ipv4", "192.0.2.1", "source2")
        engine.index_ioc("ipv4", "192.0.2.1", "source3")

        assert len(engine._ioc_index["ipv4:192.0.2.1"]) == 3

    def test_correlate_ioc_basic(self):
        engine = CorrelationEngine()
        engine.index_ioc("ipv4", "192.0.2.1", "source1", "2024-01-01T00:00:00")
        engine.index_ioc("ipv4", "192.0.2.1", "source2", "2024-01-02T00:00:00")

        result = engine.correlate_ioc("ipv4", "192.0.2.1")

        assert result.ioc_type == "ipv4"
        assert result.ioc_value == "192.0.2.1"
        assert len(result.sources) == 2
        assert "source1" in result.sources
        assert "source2" in result.sources
        assert result.first_seen == "2024-01-01T00:00:00"
        assert result.last_seen == "2024-01-02T00:00:00"

    def test_correlate_ioc_finds_related(self):
        engine = CorrelationEngine()
        # Two IOCs from same source
        engine.index_ioc("ipv4", "192.0.2.1", "intel_report")
        engine.index_ioc("domain", "evil.com", "intel_report")
        # Unrelated IOC from different source
        engine.index_ioc("ipv4", "192.0.2.2", "other_source")

        result = engine.correlate_ioc("ipv4", "192.0.2.1")

        assert len(result.related_iocs) == 1
        assert result.related_iocs[0]["type"] == "domain"
        assert result.related_iocs[0]["value"] == "evil.com"

    def test_correlate_ioc_not_found(self):
        engine = CorrelationEngine()

        result = engine.correlate_ioc("ipv4", "192.0.2.1")

        assert result.sources == []
        assert result.confidence == 0.0

    def test_confidence_calculation(self):
        engine = CorrelationEngine()
        # Add multiple sources
        engine.index_ioc("ipv4", "192.0.2.1", "source1")
        engine.index_ioc("ipv4", "192.0.2.1", "source2")
        engine.index_ioc("ipv4", "192.0.2.1", "source3")
        engine.index_ioc("ipv4", "192.0.2.1", "source4")
        # Add related IOC
        engine.index_ioc("domain", "evil.com", "source1")

        result = engine.correlate_ioc("ipv4", "192.0.2.1")

        # 4 sources = 0.4, 4 sightings = 0.2, 1 related = 0.02 = 0.62
        assert result.confidence > 0.5
        assert result.confidence <= 1.0


class TestBehaviorToTechniqueMapping:
    """Tests for behavioral mapping to ATT&CK techniques."""

    def test_map_phishing(self):
        engine = CorrelationEngine()
        result = engine.map_behavior_to_techniques("Detected phishing email campaign")

        technique_ids = [t["id"] for t in result]
        assert "T1566" in technique_ids or "T1566.001" in technique_ids

    def test_map_powershell(self):
        engine = CorrelationEngine()
        result = engine.map_behavior_to_techniques("Malicious PowerShell script executed")

        technique_ids = [t["id"] for t in result]
        assert "T1059.001" in technique_ids

    def test_map_ransomware(self):
        engine = CorrelationEngine()
        result = engine.map_behavior_to_techniques("Ransomware encrypting files detected")

        technique_ids = [t["id"] for t in result]
        assert "T1486" in technique_ids

    def test_map_credential_dump(self):
        engine = CorrelationEngine()
        result = engine.map_behavior_to_techniques("LSASS memory credential dump detected")

        technique_ids = [t["id"] for t in result]
        assert "T1003.001" in technique_ids or "T1003" in technique_ids

    def test_map_multiple_techniques(self):
        engine = CorrelationEngine()
        result = engine.map_behavior_to_techniques(
            "Attacker used spear phishing to gain access, then ran PowerShell"
        )

        technique_ids = [t["id"] for t in result]
        assert len(technique_ids) >= 2

    def test_map_no_match(self):
        engine = CorrelationEngine()
        result = engine.map_behavior_to_techniques("Normal user activity observed")

        assert result == []

    def test_confidence_scoring(self):
        engine = CorrelationEngine()
        # Text with multiple matches for same technique should have higher confidence
        result = engine.map_behavior_to_techniques(
            "PowerShell script, PowerShell command, another PowerShell"
        )

        ps_result = next((t for t in result if t["id"] == "T1059.001"), None)
        assert ps_result is not None
        assert ps_result["confidence"] > 0.3


class TestIOCClustering:
    """Tests for IOC clustering."""

    def test_cluster_by_source(self):
        engine = CorrelationEngine()
        now = datetime.now(UTC)

        iocs = [
            {
                "type": "ipv4",
                "value": "192.0.2.1",
                "source": "report1",
                "timestamp": now.isoformat(),
            },
            {
                "type": "ipv4",
                "value": "192.0.2.2",
                "source": "report1",
                "timestamp": (now + timedelta(minutes=5)).isoformat(),
            },
            {
                "type": "domain",
                "value": "evil.com",
                "source": "report1",
                "timestamp": (now + timedelta(minutes=10)).isoformat(),
            },
        ]

        clusters = engine.cluster_iocs(iocs, time_window_minutes=60, min_cluster_size=2)

        assert len(clusters) == 1
        assert len(clusters[0].members) == 3
        assert clusters[0].common_sources == ["report1"]

    def test_cluster_time_window(self):
        engine = CorrelationEngine()
        now = datetime.now(UTC)

        iocs = [
            {
                "type": "ipv4",
                "value": "192.0.2.1",
                "source": "report1",
                "timestamp": now.isoformat(),
            },
            {
                "type": "ipv4",
                "value": "192.0.2.2",
                "source": "report1",
                "timestamp": (now + timedelta(minutes=5)).isoformat(),
            },
            # This one is outside the time window
            {
                "type": "ipv4",
                "value": "192.0.2.3",
                "source": "report1",
                "timestamp": (now + timedelta(hours=3)).isoformat(),
            },
        ]

        clusters = engine.cluster_iocs(iocs, time_window_minutes=30, min_cluster_size=2)

        assert len(clusters) == 1
        assert len(clusters[0].members) == 2

    def test_cluster_min_size(self):
        engine = CorrelationEngine()
        now = datetime.now(UTC)

        iocs = [
            {
                "type": "ipv4",
                "value": "192.0.2.1",
                "source": "report1",
                "timestamp": now.isoformat(),
            },
        ]

        clusters = engine.cluster_iocs(iocs, min_cluster_size=2)

        assert len(clusters) == 0

    def test_cluster_multiple_sources(self):
        engine = CorrelationEngine()
        now = datetime.now(UTC)

        iocs = [
            {
                "type": "ipv4",
                "value": "192.0.2.1",
                "source": "source1",
                "timestamp": now.isoformat(),
            },
            {
                "type": "ipv4",
                "value": "192.0.2.2",
                "source": "source1",
                "timestamp": (now + timedelta(minutes=5)).isoformat(),
            },
            {
                "type": "domain",
                "value": "evil1.com",
                "source": "source2",
                "timestamp": now.isoformat(),
            },
            {
                "type": "domain",
                "value": "evil2.com",
                "source": "source2",
                "timestamp": (now + timedelta(minutes=5)).isoformat(),
            },
        ]

        clusters = engine.cluster_iocs(iocs, min_cluster_size=2)

        assert len(clusters) == 2

    def test_cluster_deduplication(self):
        engine = CorrelationEngine()
        now = datetime.now(UTC)

        iocs = [
            {
                "type": "ipv4",
                "value": "192.0.2.1",
                "source": "report1",
                "timestamp": now.isoformat(),
            },
            {
                "type": "ipv4",
                "value": "192.0.2.1",
                "source": "report1",
                "timestamp": (now + timedelta(minutes=5)).isoformat(),
            },  # Duplicate
            {
                "type": "ipv4",
                "value": "192.0.2.2",
                "source": "report1",
                "timestamp": (now + timedelta(minutes=10)).isoformat(),
            },
        ]

        clusters = engine.cluster_iocs(iocs, min_cluster_size=2)

        # Should have 2 unique IOCs in cluster
        assert len(clusters) == 1
        unique_values = {m["value"] for m in clusters[0].members}
        assert len(unique_values) == 2


class TestInfrastructurePatterns:
    """Tests for infrastructure pattern detection."""

    def test_detect_shared_hosting(self):
        engine = CorrelationEngine()
        domains = [
            "malware.amazonaws.com",
            "c2.digitalocean.com",
            "normal.example.com",
        ]

        results = engine.find_infrastructure_patterns(domains)

        assert "shared_hosting" in results
        assert "malware.amazonaws.com" in results["shared_hosting"]
        assert "c2.digitalocean.com" in results["shared_hosting"]

    def test_detect_dynamic_dns(self):
        engine = CorrelationEngine()
        domains = [
            "evil.duckdns.org",
            "malware.no-ip.org",
        ]

        results = engine.find_infrastructure_patterns(domains)

        assert "dynamic_dns" in results
        assert len(results["dynamic_dns"]) == 2

    def test_detect_bulletproof(self):
        engine = CorrelationEngine()
        domains = [
            "c2.dataclub.eu",
            "payload.leaseweb.com",
        ]

        results = engine.find_infrastructure_patterns(domains)

        assert "bulletproof" in results

    def test_no_patterns_found(self):
        engine = CorrelationEngine()
        domains = [
            "legitimate.com",
            "normal-business.org",
        ]

        results = engine.find_infrastructure_patterns(domains)

        assert results == {}


class TestCampaignCorrelation:
    """Tests for campaign-based correlation."""

    def test_correlate_campaign_iocs_no_manager(self):
        engine = CorrelationEngine()

        result = engine.correlate_campaign_iocs("campaign-001")

        assert "error" in result
        assert "not available" in result["error"]

    def test_correlate_campaign_iocs_not_found(self):
        # Mock campaign manager
        class MockCampaignManager:
            def get(self, campaign_id):
                return None

        engine = CorrelationEngine(campaign_manager=MockCampaignManager())

        result = engine.correlate_campaign_iocs("nonexistent")

        assert "error" in result
        assert "not found" in result["error"]
