"""Unit tests for context management system."""

import json

import pytest

from osint_agent.context import ContextManager


@pytest.fixture
def ctx(tmp_path):
    """Create a ContextManager with a temporary directory."""
    return ContextManager(tmp_path / "context")


class TestContextManagerInit:
    """Tests for ContextManager initialization."""

    def test_creates_directory(self, tmp_path):
        ctx_dir = tmp_path / "context"
        assert not ctx_dir.exists()
        ContextManager(ctx_dir)
        assert ctx_dir.exists()

    def test_accepts_string_path(self, tmp_path):
        ctx = ContextManager(str(tmp_path / "context"))
        assert ctx.context_dir.exists()


class TestContextTierValidation:
    """Tests for tier validation."""

    def test_valid_tiers(self, ctx):
        for tier in ["strategic", "operational", "tactical", "technical", "security"]:
            data = ctx.get(tier)
            assert data["tier"] == tier

    def test_invalid_tier_get(self, ctx):
        with pytest.raises(ValueError, match="Invalid tier"):
            ctx.get("invalid_tier")

    def test_invalid_tier_set(self, ctx):
        with pytest.raises(ValueError, match="Invalid tier"):
            ctx.set("invalid_tier", "key", "value")

    def test_invalid_tier_update(self, ctx):
        with pytest.raises(ValueError, match="Invalid tier"):
            ctx.update("invalid_tier", {"key": "value"})

    def test_invalid_tier_clear(self, ctx):
        with pytest.raises(ValueError, match="Invalid tier"):
            ctx.clear_tier("invalid_tier")


class TestContextDefaults:
    """Tests for default context values."""

    def test_strategic_defaults(self, ctx):
        data = ctx.get("strategic")
        assert data["tier"] == "strategic"
        assert data["objectives"] == []
        assert "threat_landscape" in data
        assert data["campaigns"] == []

    def test_operational_defaults(self, ctx):
        data = ctx.get("operational")
        assert data["tier"] == "operational"
        assert data["investigation"]["status"] == "not_started"
        assert data["requirements"] == []

    def test_tactical_defaults(self, ctx):
        data = ctx.get("tactical")
        assert data["tier"] == "tactical"
        assert data["priorities"] == []
        assert data["active_iocs"] == []
        assert data["findings"] == []

    def test_technical_defaults(self, ctx):
        data = ctx.get("technical")
        assert data["tier"] == "technical"
        assert data["api_configs"] == {}
        assert data["tool_settings"] == {}

    def test_security_defaults(self, ctx):
        data = ctx.get("security")
        assert data["tier"] == "security"
        assert data["classification"] == "unclassified"
        assert data["handling_caveats"] == []


class TestContextGetSet:
    """Tests for get/set operations."""

    def test_set_and_get_key(self, ctx):
        ctx.set("tactical", "custom_key", "custom_value")
        assert ctx.get("tactical", "custom_key") == "custom_value"

    def test_get_nonexistent_key(self, ctx):
        assert ctx.get("tactical", "nonexistent") is None

    def test_get_full_tier(self, ctx):
        data = ctx.get("tactical")
        assert isinstance(data, dict)
        assert "tier" in data

    def test_overwrite_value(self, ctx):
        ctx.set("tactical", "key", "value1")
        ctx.set("tactical", "key", "value2")
        assert ctx.get("tactical", "key") == "value2"

    def test_set_complex_value(self, ctx):
        ctx.set("tactical", "nested", {"a": [1, 2, 3], "b": {"c": True}})
        result = ctx.get("tactical", "nested")
        assert result == {"a": [1, 2, 3], "b": {"c": True}}


class TestContextUpdate:
    """Tests for batch update operations."""

    def test_update_multiple_keys(self, ctx):
        ctx.update("tactical", {"key1": "val1", "key2": "val2"})
        assert ctx.get("tactical", "key1") == "val1"
        assert ctx.get("tactical", "key2") == "val2"

    def test_update_preserves_existing(self, ctx):
        ctx.set("tactical", "existing", "keep")
        ctx.update("tactical", {"new_key": "new_val"})
        assert ctx.get("tactical", "existing") == "keep"
        assert ctx.get("tactical", "new_key") == "new_val"


class TestContextAppend:
    """Tests for list append operations."""

    def test_append_to_existing_list(self, ctx):
        ctx.append("tactical", "priorities", "first")
        ctx.append("tactical", "priorities", "second")
        assert ctx.get("tactical", "priorities") == ["first", "second"]

    def test_append_creates_list_if_missing(self, ctx):
        ctx.append("tactical", "new_list", "item")
        assert ctx.get("tactical", "new_list") == ["item"]

    def test_append_to_non_list_raises(self, ctx):
        ctx.set("tactical", "not_a_list", "string")
        with pytest.raises(ValueError, match="not a list"):
            ctx.append("tactical", "not_a_list", "item")


class TestContextPersistence:
    """Tests for file-based persistence."""

    def test_data_persists_across_instances(self, tmp_path):
        ctx_dir = tmp_path / "context"
        ctx1 = ContextManager(ctx_dir)
        ctx1.set("tactical", "persistent_key", "persistent_value")

        # New instance, same directory
        ctx2 = ContextManager(ctx_dir)
        assert ctx2.get("tactical", "persistent_key") == "persistent_value"

    def test_file_created_on_first_access(self, ctx):
        ctx.get("strategic")
        path = ctx.context_dir / "strategic_context.json"
        assert path.exists()

    def test_file_is_valid_json(self, ctx):
        ctx.set("tactical", "key", "value")
        path = ctx.context_dir / "tactical_context.json"
        data = json.loads(path.read_text())
        assert data["key"] == "value"

    def test_last_modified_updated(self, ctx):
        ctx.set("tactical", "key", "value")
        data = ctx.get("tactical")
        assert "last_modified" in data

    def test_corrupted_file_returns_default(self, ctx):
        # Write invalid JSON
        path = ctx.context_dir / "tactical_context.json"
        path.write_text("not valid json{{{")
        # Clear cache to force re-read
        ctx._cache.clear()
        data = ctx.get("tactical")
        assert data["tier"] == "tactical"


class TestContextGetAll:
    """Tests for get_all and get_summary."""

    def test_get_all_returns_all_tiers(self, ctx):
        all_ctx = ctx.get_all()
        assert set(all_ctx.keys()) == {"strategic", "operational", "tactical", "technical", "security"}

    def test_get_summary(self, ctx):
        summary = ctx.get_summary()
        assert "strategic" in summary
        assert "operational" in summary
        assert "tactical" in summary
        assert "security" in summary
        assert summary["security"]["classification"] == "unclassified"


class TestContextClearTier:
    """Tests for clearing tiers."""

    def test_clear_resets_to_defaults(self, ctx):
        ctx.set("tactical", "custom", "data")
        ctx.append("tactical", "priorities", "something")
        ctx.clear_tier("tactical")
        data = ctx.get("tactical")
        assert data["priorities"] == []
        assert data.get("custom") is None


class TestInvestigationWorkflow:
    """Tests for investigation lifecycle."""

    def test_start_investigation(self, ctx):
        ctx.start_investigation(
            name="Test Investigation",
            description="Testing the system",
            scope="internal network",
            stakeholders=["analyst"],
        )
        op = ctx.get("operational")
        assert op["investigation"]["name"] == "Test Investigation"
        assert op["investigation"]["status"] == "in_progress"
        assert op["investigation"]["scope"] == "internal network"
        assert "started" in op["investigation"]

    def test_start_investigation_resets_tactical(self, ctx):
        ctx.append("tactical", "priorities", "old priority")
        ctx.start_investigation(name="New Investigation")
        assert ctx.get("tactical", "priorities") == []

    def test_add_ioc(self, ctx):
        ctx.add_ioc(
            ioc_type="ipv4",
            value="1.2.3.4",
            confidence=0.8,
            source="otx",
            tags=["c2"],
        )
        iocs = ctx.get("tactical", "active_iocs")
        assert len(iocs) == 1
        assert iocs[0]["type"] == "ipv4"
        assert iocs[0]["value"] == "1.2.3.4"
        assert iocs[0]["confidence"] == 0.8
        assert iocs[0]["tags"] == ["c2"]

    def test_add_finding(self, ctx):
        ctx.add_finding(
            title="C2 Communication",
            description="Host communicating with known C2",
            confidence=0.9,
            evidence=["pcap_001", "dns_log_123"],
        )
        findings = ctx.get("tactical", "findings")
        assert len(findings) == 1
        assert findings[0]["title"] == "C2 Communication"
        assert findings[0]["confidence"] == 0.9
        assert len(findings[0]["evidence"]) == 2

    def test_multiple_iocs(self, ctx):
        ctx.add_ioc("ipv4", "1.2.3.4", source="otx")
        ctx.add_ioc("domain", "evil.com", source="urlhaus")
        iocs = ctx.get("tactical", "active_iocs")
        assert len(iocs) == 2

    def test_full_workflow(self, ctx):
        # Start investigation
        ctx.start_investigation(name="APT29 Investigation")
        # Add IOCs
        ctx.add_ioc("ipv4", "1.2.3.4", confidence=0.9, source="otx")
        ctx.add_ioc("domain", "c2.evil.com", confidence=0.7, source="urlhaus")
        # Add finding
        ctx.add_finding("C2 Beacon", "Regular beaconing pattern detected", confidence=0.85)
        # Verify state
        summary = ctx.get_summary()
        assert summary["operational"]["investigation"] == "APT29 Investigation"
        assert summary["operational"]["status"] == "in_progress"
        assert summary["tactical"]["active_ioc_count"] == 2
        assert summary["tactical"]["finding_count"] == 1
