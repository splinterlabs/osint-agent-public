"""Unit tests for campaign management."""

import json
import tempfile
from pathlib import Path

import pytest

from osint_agent.campaigns import (
    Campaign,
    CampaignIOC,
    CampaignManager,
    CampaignStatus,
    CampaignTTP,
    ConfidenceLevel,
)


class TestCampaignIOC:
    """Tests for CampaignIOC dataclass."""

    def test_to_dict(self):
        ioc = CampaignIOC(
            ioc_type="ipv4",
            value="192.0.2.1",
            first_seen="2024-01-01T00:00:00",
            last_seen="2024-01-02T00:00:00",
            source="test",
            confidence=ConfidenceLevel.HIGH,
            tags=["malware", "c2"],
            notes="Test IOC",
        )
        result = ioc.to_dict()

        assert result["ioc_type"] == "ipv4"
        assert result["value"] == "192.0.2.1"
        assert result["confidence"] == "high"
        assert "malware" in result["tags"]

    def test_from_dict(self):
        data = {
            "ioc_type": "domain",
            "value": "evil.com",
            "first_seen": "2024-01-01T00:00:00",
            "last_seen": "2024-01-02T00:00:00",
            "source": "intel",
            "confidence": "medium",
            "tags": ["phishing"],
            "notes": "",
        }
        ioc = CampaignIOC.from_dict(data)

        assert ioc.ioc_type == "domain"
        assert ioc.value == "evil.com"
        assert ioc.confidence == ConfidenceLevel.MEDIUM


class TestCampaignTTP:
    """Tests for CampaignTTP dataclass."""

    def test_to_dict(self):
        ttp = CampaignTTP(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            observed_at="2024-01-01T00:00:00",
            evidence="Encoded PowerShell detected",
            confidence=ConfidenceLevel.CONFIRMED,
        )
        result = ttp.to_dict()

        assert result["technique_id"] == "T1059.001"
        assert result["technique_name"] == "PowerShell"
        assert result["confidence"] == "confirmed"

    def test_from_dict(self):
        data = {
            "technique_id": "T1566",
            "technique_name": "Phishing",
            "tactic": "Initial Access",
            "observed_at": "2024-01-01T00:00:00",
            "evidence": "Phishing email detected",
            "confidence": "high",
        }
        ttp = CampaignTTP.from_dict(data)

        assert ttp.technique_id == "T1566"
        assert ttp.confidence == ConfidenceLevel.HIGH


class TestCampaign:
    """Tests for Campaign dataclass."""

    def test_add_ioc_new(self):
        campaign = Campaign(
            id="test-001",
            name="Test Campaign",
            description="Test",
            status=CampaignStatus.ACTIVE,
            created_at="2024-01-01T00:00:00",
            updated_at="2024-01-01T00:00:00",
        )

        ioc = campaign.add_ioc(
            ioc_type="ipv4",
            value="192.0.2.1",
            source="test",
            tags=["c2"],
        )

        assert len(campaign.iocs) == 1
        assert ioc.value == "192.0.2.1"
        assert "c2" in ioc.tags

    def test_add_ioc_existing_updates(self):
        campaign = Campaign(
            id="test-001",
            name="Test Campaign",
            description="Test",
            status=CampaignStatus.ACTIVE,
            created_at="2024-01-01T00:00:00",
            updated_at="2024-01-01T00:00:00",
        )

        # Add same IOC twice
        campaign.add_ioc(ioc_type="ipv4", value="192.0.2.1", source="source1", tags=["tag1"])
        campaign.add_ioc(ioc_type="ipv4", value="192.0.2.1", source="source2", tags=["tag2"])

        # Should still be one IOC with updated source and merged tags
        assert len(campaign.iocs) == 1
        assert campaign.iocs[0].source == "source2"
        assert "tag1" in campaign.iocs[0].tags
        assert "tag2" in campaign.iocs[0].tags

    def test_add_ttp_new(self):
        campaign = Campaign(
            id="test-001",
            name="Test Campaign",
            description="Test",
            status=CampaignStatus.ACTIVE,
            created_at="2024-01-01T00:00:00",
            updated_at="2024-01-01T00:00:00",
        )

        ttp = campaign.add_ttp(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            evidence="Encoded commands",
        )

        assert len(campaign.ttps) == 1
        assert ttp.technique_id == "T1059.001"

    def test_add_ttp_existing_updates(self):
        campaign = Campaign(
            id="test-001",
            name="Test Campaign",
            description="Test",
            status=CampaignStatus.ACTIVE,
            created_at="2024-01-01T00:00:00",
            updated_at="2024-01-01T00:00:00",
        )

        campaign.add_ttp(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            evidence="Evidence 1",
        )
        campaign.add_ttp(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            evidence="Evidence 2",
        )

        assert len(campaign.ttps) == 1
        assert campaign.ttps[0].evidence == "Evidence 2"

    def test_add_cve(self):
        campaign = Campaign(
            id="test-001",
            name="Test Campaign",
            description="Test",
            status=CampaignStatus.ACTIVE,
            created_at="2024-01-01T00:00:00",
            updated_at="2024-01-01T00:00:00",
        )

        campaign.add_cve("CVE-2024-1234")
        campaign.add_cve("CVE-2024-1234")  # Duplicate
        campaign.add_cve("CVE-2024-5678")

        assert len(campaign.cves) == 2
        assert "CVE-2024-1234" in campaign.cves
        assert "CVE-2024-5678" in campaign.cves

    def test_update_status(self):
        campaign = Campaign(
            id="test-001",
            name="Test Campaign",
            description="Test",
            status=CampaignStatus.ACTIVE,
            created_at="2024-01-01T00:00:00",
            updated_at="2024-01-01T00:00:00",
        )

        original_updated = campaign.updated_at
        campaign.update_status(CampaignStatus.RESOLVED)

        assert campaign.status == CampaignStatus.RESOLVED
        assert campaign.updated_at != original_updated

    def test_to_dict_and_from_dict_roundtrip(self):
        original = Campaign(
            id="test-001",
            name="Test Campaign",
            description="A test campaign",
            status=CampaignStatus.ACTIVE,
            created_at="2024-01-01T00:00:00",
            updated_at="2024-01-02T00:00:00",
            threat_actor="APT99",
            threat_actor_aliases=["ThreatGroup", "BadActor"],
            targeted_sectors=["Finance", "Healthcare"],
            targeted_regions=["US", "EU"],
            malware_families=["Emotet"],
            cves=["CVE-2024-1234"],
            tags=["ransomware"],
            notes="Test notes",
        )
        original.add_ioc("ipv4", "192.0.2.1", "test")
        original.add_ttp("T1059", "Scripting", "Execution", "Evidence")

        data = original.to_dict()
        restored = Campaign.from_dict(data)

        assert restored.id == original.id
        assert restored.name == original.name
        assert restored.threat_actor == original.threat_actor
        assert len(restored.iocs) == 1
        assert len(restored.ttps) == 1


class TestCampaignManager:
    """Tests for CampaignManager."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_create_campaign(self, temp_dir):
        manager = CampaignManager(data_dir=temp_dir)
        campaign = manager.create(
            name="New Campaign",
            description="Test description",
            threat_actor="APT1",
            tags=["apt"],
        )

        assert campaign.name == "New Campaign"
        assert campaign.status == CampaignStatus.ACTIVE
        assert campaign.threat_actor == "APT1"
        assert len(campaign.id) == 8

    def test_get_campaign(self, temp_dir):
        manager = CampaignManager(data_dir=temp_dir)
        created = manager.create(name="Test", description="Test")

        retrieved = manager.get(created.id)

        assert retrieved is not None
        assert retrieved.id == created.id
        assert retrieved.name == "Test"

    def test_get_campaign_not_found(self, temp_dir):
        manager = CampaignManager(data_dir=temp_dir)

        result = manager.get("nonexistent")

        assert result is None

    def test_get_by_name(self, temp_dir):
        manager = CampaignManager(data_dir=temp_dir)
        manager.create(name="APT Campaign", description="Test")

        result = manager.get_by_name("apt campaign")  # Case-insensitive

        assert result is not None
        assert result.name == "APT Campaign"

    def test_list_campaigns(self, temp_dir):
        manager = CampaignManager(data_dir=temp_dir)
        manager.create(name="Campaign 1", description="Test 1")
        manager.create(name="Campaign 2", description="Test 2")

        results = manager.list()

        assert len(results) == 2

    def test_list_campaigns_filter_by_status(self, temp_dir):
        manager = CampaignManager(data_dir=temp_dir)
        manager.create(name="Active Campaign", description="Test")
        c2 = manager.create(name="Resolved Campaign", description="Test")
        c2.update_status(CampaignStatus.RESOLVED)
        manager.update(c2)

        active = manager.list(status=CampaignStatus.ACTIVE)
        resolved = manager.list(status=CampaignStatus.RESOLVED)

        assert len(active) == 1
        assert active[0].name == "Active Campaign"
        assert len(resolved) == 1
        assert resolved[0].name == "Resolved Campaign"

    def test_list_campaigns_filter_by_threat_actor(self, temp_dir):
        manager = CampaignManager(data_dir=temp_dir)
        manager.create(name="APT1 Campaign", description="Test", threat_actor="APT1")
        manager.create(name="APT2 Campaign", description="Test", threat_actor="APT2")

        results = manager.list(threat_actor="APT1")

        assert len(results) == 1
        assert results[0].name == "APT1 Campaign"

    def test_list_campaigns_filter_by_tag(self, temp_dir):
        manager = CampaignManager(data_dir=temp_dir)
        manager.create(name="Ransomware Campaign", description="Test", tags=["ransomware"])
        manager.create(name="Phishing Campaign", description="Test", tags=["phishing"])

        results = manager.list(tag="ransomware")

        assert len(results) == 1
        assert results[0].name == "Ransomware Campaign"

    def test_update_campaign(self, temp_dir):
        manager = CampaignManager(data_dir=temp_dir)
        campaign = manager.create(name="Test", description="Original")
        campaign.description = "Updated"
        manager.update(campaign)

        # Reload to verify persistence
        manager2 = CampaignManager(data_dir=temp_dir)
        retrieved = manager2.get(campaign.id)

        assert retrieved.description == "Updated"

    def test_delete_campaign(self, temp_dir):
        manager = CampaignManager(data_dir=temp_dir)
        campaign = manager.create(name="To Delete", description="Test")
        campaign_id = campaign.id

        result = manager.delete(campaign_id)

        assert result is True
        assert manager.get(campaign_id) is None

    def test_delete_nonexistent(self, temp_dir):
        manager = CampaignManager(data_dir=temp_dir)

        result = manager.delete("nonexistent")

        assert result is False

    def test_find_by_ioc(self, temp_dir):
        manager = CampaignManager(data_dir=temp_dir)
        c1 = manager.create(name="Campaign 1", description="Test")
        c1.add_ioc("ipv4", "192.0.2.1", "test")
        manager.update(c1)

        c2 = manager.create(name="Campaign 2", description="Test")
        c2.add_ioc("ipv4", "192.0.2.2", "test")
        manager.update(c2)

        results = manager.find_by_ioc("ipv4", "192.0.2.1")

        assert len(results) == 1
        assert results[0].name == "Campaign 1"

    def test_find_by_ttp(self, temp_dir):
        manager = CampaignManager(data_dir=temp_dir)
        c1 = manager.create(name="Campaign 1", description="Test")
        c1.add_ttp("T1059.001", "PowerShell", "Execution", "Evidence")
        manager.update(c1)

        c2 = manager.create(name="Campaign 2", description="Test")
        c2.add_ttp("T1566", "Phishing", "Initial Access", "Evidence")
        manager.update(c2)

        results = manager.find_by_ttp("T1059.001")

        assert len(results) == 1
        assert results[0].name == "Campaign 1"

    def test_find_by_cve(self, temp_dir):
        manager = CampaignManager(data_dir=temp_dir)
        c1 = manager.create(name="Campaign 1", description="Test")
        c1.add_cve("CVE-2024-1234")
        manager.update(c1)

        results = manager.find_by_cve("CVE-2024-1234")

        assert len(results) == 1
        assert results[0].name == "Campaign 1"

    def test_get_statistics(self, temp_dir):
        manager = CampaignManager(data_dir=temp_dir)
        c1 = manager.create(name="Active", description="Test")
        c1.add_ioc("ipv4", "192.0.2.1", "test")
        c1.add_ttp("T1059", "Scripting", "Execution", "Evidence")
        manager.update(c1)

        c2 = manager.create(name="Resolved", description="Test")
        c2.update_status(CampaignStatus.RESOLVED)
        manager.update(c2)

        stats = manager.get_statistics()

        assert stats["total_campaigns"] == 2
        assert stats["by_status"]["active"] == 1
        assert stats["by_status"]["resolved"] == 1
        assert stats["total_iocs"] == 1
        assert stats["total_ttps"] == 1

    def test_persistence_across_instances(self, temp_dir):
        # Create and save
        manager1 = CampaignManager(data_dir=temp_dir)
        campaign = manager1.create(name="Persistent", description="Test")
        campaign.add_ioc("domain", "evil.com", "test")
        manager1.update(campaign)

        # Load in new instance
        manager2 = CampaignManager(data_dir=temp_dir)
        loaded = manager2.get(campaign.id)

        assert loaded is not None
        assert loaded.name == "Persistent"
        assert len(loaded.iocs) == 1
        assert loaded.iocs[0].value == "evil.com"

    def test_storage_file_created(self, temp_dir):
        manager = CampaignManager(data_dir=temp_dir)
        manager.create(name="Test", description="Test")

        storage_file = temp_dir / "campaigns.json"
        assert storage_file.exists()

        with open(storage_file) as f:
            data = json.load(f)
            assert "campaigns" in data
            assert len(data["campaigns"]) == 1
