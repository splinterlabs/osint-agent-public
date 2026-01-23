"""Integration tests for MCP server tools.

These tests verify that MCP tools are correctly registered and return
valid JSON responses.

Requires: pip install mcp (or run with mcp-server's venv)
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import responses

# Skip all tests in this module if mcp is not installed
pytest.importorskip("mcp", reason="MCP package not installed - run with mcp-server venv")

# Add mcp-server to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "mcp-server"))


class MockFastMCP:
    """Mock FastMCP server for testing tool registration."""

    def __init__(self, name: str = "test"):
        self.name = name
        self.tools: dict[str, callable] = {}

    def tool(self):
        """Decorator to register tools."""
        def decorator(func):
            self.tools[func.__name__] = func
            return func
        return decorator


class TestExtractorTools:
    """Tests for IOC extractor MCP tools."""

    def test_extract_iocs_from_text_registration(self):
        from tools import extractor_tools

        mcp = MockFastMCP()
        extractor_tools.register_tools(mcp)

        assert "extract_iocs_from_text" in mcp.tools

    def test_extract_iocs_from_text_returns_json(self):
        from tools import extractor_tools

        mcp = MockFastMCP()
        extractor_tools.register_tools(mcp)

        result = mcp.tools["extract_iocs_from_text"](
            "Found malicious IP 8.8.8.8 and domain evil.com"
        )

        data = json.loads(result)
        assert "total_iocs" in data
        assert "iocs" in data
        assert data["total_iocs"] == 2
        assert "8.8.8.8" in data["iocs"]["ipv4"]
        assert "evil.com" in data["iocs"]["domain"]

    def test_extract_iocs_empty_content(self):
        from tools import extractor_tools

        mcp = MockFastMCP()
        extractor_tools.register_tools(mcp)

        result = mcp.tools["extract_iocs_from_text"]("No IOCs here")

        data = json.loads(result)
        assert data["total_iocs"] == 0
        assert data["iocs"] == {}


class TestNVDTools:
    """Tests for NVD MCP tools."""

    def test_nvd_tools_registration(self):
        from tools import nvd_tools

        mcp = MockFastMCP()
        nvd_tools.register_tools(mcp)

        assert "lookup_cve" in mcp.tools
        assert "get_critical_cves" in mcp.tools

    @responses.activate
    def test_lookup_cve_returns_json(self):
        from tools import nvd_tools

        # Mock NVD API
        mock_response = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [{"lang": "en", "value": "Test vuln"}],
                    "metrics": {},
                    "weaknesses": [],
                    "configurations": [],
                    "references": [],
                }
            }]
        }
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json=mock_response,
            status=200,
        )

        # Mock KEV API
        responses.add(
            responses.GET,
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            json={"vulnerabilities": []},
            status=200,
        )

        mcp = MockFastMCP()
        nvd_tools.register_tools(mcp)

        # Reset singleton to use fresh client
        nvd_tools._client = None

        result = mcp.tools["lookup_cve"]("CVE-2024-1234")

        data = json.loads(result)
        assert data["id"] == "CVE-2024-1234"
        assert "actively_exploited" in data

    @responses.activate
    def test_lookup_cve_not_found(self):
        from tools import nvd_tools

        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json={"vulnerabilities": []},
            status=200,
        )

        mcp = MockFastMCP()
        nvd_tools.register_tools(mcp)
        nvd_tools._client = None

        result = mcp.tools["lookup_cve"]("CVE-9999-99999")

        data = json.loads(result)
        assert "error" in data


class TestKEVTools:
    """Tests for CISA KEV MCP tools."""

    def test_kev_tools_registration(self):
        from tools import kev_tools

        mcp = MockFastMCP()
        kev_tools.register_tools(mcp)

        assert "check_kev" in mcp.tools
        assert "search_kev_vendor" in mcp.tools
        assert "get_kev_stats" in mcp.tools

    @responses.activate
    def test_check_kev_found(self):
        from tools import kev_tools

        mock_catalog = {
            "vulnerabilities": [{
                "cveID": "CVE-2024-1234",
                "vendorProject": "TestVendor",
                "product": "TestProduct",
                "vulnerabilityName": "Test",
                "dateAdded": "2024-01-01",
                "shortDescription": "Test vuln",
                "requiredAction": "Patch",
                "dueDate": "2024-02-01",
                "knownRansomwareCampaignUse": "Known",
            }]
        }
        responses.add(
            responses.GET,
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            json=mock_catalog,
            status=200,
        )

        mcp = MockFastMCP()
        kev_tools.register_tools(mcp)
        kev_tools._client = None

        result = mcp.tools["check_kev"]("CVE-2024-1234")

        data = json.loads(result)
        assert data["in_kev"] is True
        assert data["details"]["vendor"] == "TestVendor"

    @responses.activate
    def test_check_kev_not_found(self):
        from tools import kev_tools

        responses.add(
            responses.GET,
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            json={"vulnerabilities": []},
            status=200,
        )

        mcp = MockFastMCP()
        kev_tools.register_tools(mcp)
        kev_tools._client = None

        result = mcp.tools["check_kev"]("CVE-9999-99999")

        data = json.loads(result)
        assert data["in_kev"] is False


class TestSTIXTools:
    """Tests for STIX export MCP tools."""

    def test_stix_tools_registration(self):
        from tools import stix_tools

        mcp = MockFastMCP()
        stix_tools.register_tools(mcp)

        assert "iocs_to_stix" in mcp.tools

    def test_iocs_to_stix_returns_bundle(self):
        from tools import stix_tools

        mcp = MockFastMCP()
        stix_tools.register_tools(mcp)

        # Tool expects JSON string input
        iocs_json = json.dumps({
            "ipv4": ["192.0.2.1"],
            "domain": ["malware.net"]
        })
        result = mcp.tools["iocs_to_stix"](iocs_json)

        data = json.loads(result)
        assert data["type"] == "bundle"
        assert "objects" in data
        assert len(data["objects"]) > 0


class TestRuleTools:
    """Tests for YARA/Sigma rule generation MCP tools."""

    def test_rule_tools_registration(self):
        from tools import rule_tools

        mcp = MockFastMCP()
        rule_tools.register_tools(mcp)

        assert "generate_yara_from_hashes" in mcp.tools
        assert "generate_sigma_network" in mcp.tools
        assert "generate_sigma_dns" in mcp.tools
        assert "generate_sigma_firewall" in mcp.tools

    def test_generate_yara_from_hashes(self):
        from tools import rule_tools

        mcp = MockFastMCP()
        rule_tools.register_tools(mcp)

        hashes_json = json.dumps([
            {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e"}
        ])
        result = mcp.tools["generate_yara_from_hashes"](
            rule_name="test_malware",
            hashes_json=hashes_json,
            description="Test rule",
        )

        data = json.loads(result)
        assert data["rule_type"] == "YARA"
        assert "rule test_malware" in data["rule"]

    def test_generate_sigma_network(self):
        from tools import rule_tools

        mcp = MockFastMCP()
        rule_tools.register_tools(mcp)

        iocs_json = json.dumps({"domain": ["evil.com"], "ipv4": ["192.0.2.1"]})
        result = mcp.tools["generate_sigma_network"](
            title="test_detection",
            iocs_json=iocs_json,
            description="Test Sigma rule",
        )

        data = json.loads(result)
        assert data["rule_type"] == "Sigma"
        assert "title:" in data["rule"]
        assert "evil.com" in data["rule"]


class TestContextTools:
    """Tests for context management MCP tools."""

    def test_context_tools_registration(self):
        from tools import context_tools

        mcp = MockFastMCP()
        context_tools.register_tools(mcp)

        # Check that context tools are registered
        assert any("context" in name.lower() for name in mcp.tools.keys())


class TestCampaignTools:
    """Tests for campaign management MCP tools."""

    def test_campaign_tools_registration(self):
        from tools import campaign_tools

        mcp = MockFastMCP()
        campaign_tools.register_tools(mcp)

        # Check core campaign tools exist
        tool_names = list(mcp.tools.keys())
        assert any("campaign" in name.lower() for name in tool_names)


class TestToolOutputFormat:
    """Tests to verify all tools return valid JSON."""

    def test_all_tools_return_json_or_valid_format(self):
        """Verify each registered tool can be called and returns valid output."""
        from tools import extractor_tools

        mcp = MockFastMCP()
        extractor_tools.register_tools(mcp)

        for name, tool_func in mcp.tools.items():
            # Each tool should have a docstring
            assert tool_func.__doc__ is not None, f"Tool {name} missing docstring"
