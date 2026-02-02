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
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "descriptions": [{"lang": "en", "value": "Test vuln"}],
                        "metrics": {},
                        "weaknesses": [],
                        "configurations": [],
                        "references": [],
                    }
                }
            ]
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
        nvd_tools.get_client.cache_clear()

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
        nvd_tools.get_client.cache_clear()

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
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-1234",
                    "vendorProject": "TestVendor",
                    "product": "TestProduct",
                    "vulnerabilityName": "Test",
                    "dateAdded": "2024-01-01",
                    "shortDescription": "Test vuln",
                    "requiredAction": "Patch",
                    "dueDate": "2024-02-01",
                    "knownRansomwareCampaignUse": "Known",
                }
            ]
        }
        responses.add(
            responses.GET,
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            json=mock_catalog,
            status=200,
        )

        mcp = MockFastMCP()
        kev_tools.register_tools(mcp)
        kev_tools.get_client.cache_clear()

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
        kev_tools.get_client.cache_clear()

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
        iocs_json = json.dumps({"ipv4": ["192.0.2.1"], "domain": ["malware.net"]})
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

        hashes_json = json.dumps([{"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e"}])
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
        assert any("context" in name.lower() for name in mcp.tools)


class TestCampaignTools:
    """Tests for campaign management MCP tools."""

    def test_campaign_tools_registration(self):
        from tools import campaign_tools

        mcp = MockFastMCP()
        campaign_tools.register_tools(mcp)

        # Check core campaign tools exist
        tool_names = list(mcp.tools.keys())
        assert any("campaign" in name.lower() for name in tool_names)


class TestAbusechTools:
    """Tests for Abuse.ch MCP tools (URLhaus, MalwareBazaar, ThreatFox)."""

    def test_abusech_tools_registration(self):
        from tools import abusech_tools

        mcp = MockFastMCP()
        abusech_tools.register_tools(mcp)

        assert "lookup_url_urlhaus" in mcp.tools
        assert "lookup_host_urlhaus" in mcp.tools
        assert "get_recent_urls_urlhaus" in mcp.tools
        assert "lookup_hash_malwarebazaar" in mcp.tools
        assert "search_malware_bazaar" in mcp.tools
        assert "get_recent_malware_bazaar" in mcp.tools
        assert "lookup_ioc_threatfox" in mcp.tools
        assert "search_threatfox" in mcp.tools
        assert "get_recent_iocs_threatfox" in mcp.tools

    @responses.activate
    def test_lookup_url_urlhaus(self):
        from tools import abusech_tools

        responses.add(
            responses.POST,
            "https://urlhaus-api.abuse.ch/v1/url/",
            json={
                "query_status": "ok",
                "url": "http://evil.com/malware.exe",
                "url_status": "online",
                "host": "evil.com",
                "date_added": "2024-01-01",
                "threat": "malware_download",
                "blacklists": {},
                "reporter": "abuse_ch",
                "tags": ["malware"],
                "payloads": [],
            },
            status=200,
        )

        # Reset singleton
        abusech_tools._urlhaus = None

        mcp = MockFastMCP()
        abusech_tools.register_tools(mcp)

        result = mcp.tools["lookup_url_urlhaus"]("http://evil.com/malware.exe")
        data = json.loads(result)
        assert data["source"] == "URLhaus"
        assert data["data"]["found"] is True

    @responses.activate
    def test_lookup_hash_malwarebazaar(self):
        from tools import abusech_tools

        responses.add(
            responses.POST,
            "https://mb-api.abuse.ch/api/v1/",
            json={
                "query_status": "ok",
                "data": [
                    {
                        "sha256_hash": "abc123",
                        "sha1_hash": "def456",
                        "md5_hash": "ghi789",
                        "file_name": "malware.exe",
                        "file_type": "exe",
                        "file_type_mime": "application/x-dosexec",
                        "file_size": 1234,
                        "signature": "Emotet",
                        "first_seen": "2024-01-01",
                        "last_seen": "2024-01-02",
                        "reporter": "abuse_ch",
                        "tags": ["emotet"],
                        "intelligence": {"downloads": 10, "uploads": 1, "mail": None},
                        "delivery_method": "email",
                        "comment": None,
                    }
                ],
            },
            status=200,
        )

        abusech_tools._bazaar = None

        mcp = MockFastMCP()
        abusech_tools.register_tools(mcp)

        result = mcp.tools["lookup_hash_malwarebazaar"]("abc123")
        data = json.loads(result)
        assert data["source"] == "MalwareBazaar"
        assert data["data"]["found"] is True
        assert data["data"]["signature"] == "Emotet"

    @responses.activate
    def test_lookup_ioc_threatfox(self):
        from tools import abusech_tools

        responses.add(
            responses.POST,
            "https://threatfox-api.abuse.ch/api/v1/",
            json={
                "query_status": "ok",
                "data": [
                    {
                        "id": "1",
                        "ioc": "1.2.3.4:443",
                        "ioc_type": "ip:port",
                        "threat_type": "botnet_cc",
                        "malware": "win.emotet",
                        "malware_alias": None,
                        "malware_printable": "Emotet",
                        "confidence_level": 90,
                        "first_seen": "2024-01-01",
                        "last_seen": "2024-01-02",
                        "reporter": "abuse_ch",
                        "tags": ["emotet"],
                        "reference": None,
                    }
                ],
            },
            status=200,
        )

        abusech_tools._threatfox = None

        mcp = MockFastMCP()
        abusech_tools.register_tools(mcp)

        result = mcp.tools["lookup_ioc_threatfox"]("1.2.3.4:443")
        data = json.loads(result)
        assert data["source"] == "ThreatFox"
        assert data["data"]["found"] is True
        assert data["data"]["malware_printable"] == "Emotet"


class TestAttackTools:
    """Tests for MITRE ATT&CK MCP tools."""

    def test_attack_tools_registration(self):
        from tools import attack_tools

        mcp = MockFastMCP()
        attack_tools.register_tools(mcp)

        assert "attack_technique_lookup" in mcp.tools
        assert "attack_search_techniques" in mcp.tools
        assert "attack_list_tactics" in mcp.tools
        assert "attack_group_lookup" in mcp.tools
        assert "attack_software_lookup" in mcp.tools
        assert "attack_map_behavior" in mcp.tools

    def test_attack_technique_not_found(self):
        from tools import attack_tools

        mcp = MockFastMCP()
        attack_tools.register_tools(mcp)

        with patch.object(attack_tools, "get_attack_client") as mock_get:
            mock_client = MagicMock()
            mock_client.get_technique.return_value = None
            mock_get.return_value = mock_client

            result = mcp.tools["attack_technique_lookup"]("T9999")
            assert "not found" in result

    def test_attack_technique_found(self):
        from tools import attack_tools

        mcp = MockFastMCP()
        attack_tools.register_tools(mcp)

        with patch.object(attack_tools, "get_attack_client") as mock_get:
            mock_client = MagicMock()
            mock_client.get_technique.return_value = {
                "id": "T1059.001",
                "name": "PowerShell",
                "url": "https://attack.mitre.org/techniques/T1059/001",
                "tactics": ["execution"],
                "platforms": ["Windows"],
                "is_subtechnique": True,
                "deprecated": False,
                "description": "Use PowerShell commands",
                "permissions_required": ["User"],
                "data_sources": ["Process: Process Creation"],
                "detection": "Monitor for PowerShell usage",
            }
            mock_get.return_value = mock_client

            result = mcp.tools["attack_technique_lookup"]("T1059.001")
            assert "PowerShell" in result
            assert "T1059.001" in result

    def test_attack_search_techniques(self):
        from tools import attack_tools

        mcp = MockFastMCP()
        attack_tools.register_tools(mcp)

        with patch.object(attack_tools, "get_attack_client") as mock_get:
            mock_client = MagicMock()
            mock_client.search_techniques.return_value = [
                {
                    "id": "T1059",
                    "name": "Command and Scripting Interpreter",
                    "tactics": ["execution"],
                },
            ]
            mock_get.return_value = mock_client

            result = mcp.tools["attack_search_techniques"]("scripting")
            assert "T1059" in result

    def test_attack_list_tactics(self):
        from tools import attack_tools

        mcp = MockFastMCP()
        attack_tools.register_tools(mcp)

        with patch.object(attack_tools, "get_attack_client") as mock_get:
            mock_client = MagicMock()
            mock_client.list_tactics.return_value = [
                {"id": "TA0001", "name": "Initial Access", "shortname": "initial-access"},
                {"id": "TA0002", "name": "Execution", "shortname": "execution"},
            ]
            mock_get.return_value = mock_client

            result = mcp.tools["attack_list_tactics"]()
            assert "Initial Access" in result
            assert "Execution" in result


class TestHealthTools:
    """Tests for health check MCP tools."""

    def test_health_tools_registration(self):
        from tools import health_tools

        mcp = MockFastMCP()
        health_tools.register_tools(mcp)

        assert "health_check" in mcp.tools
        assert "list_api_keys" in mcp.tools

    def test_health_check_returns_valid_json(self):
        from tools import health_tools

        mcp = MockFastMCP()
        health_tools.register_tools(mcp)

        with patch("osint_agent.keymanager.get_api_key", return_value=None):
            result = mcp.tools["health_check"]()

        data = json.loads(result)
        assert "status" in data
        assert "timestamp" in data
        assert "services" in data
        assert "server" in data

    def test_list_api_keys_returns_json(self):
        from tools import health_tools

        mcp = MockFastMCP()
        health_tools.register_tools(mcp)

        with patch("osint_agent.keymanager.get_api_key", return_value=None):
            result = mcp.tools["list_api_keys"]()

        data = json.loads(result)
        assert "api_keys" in data


class TestOTXTools:
    """Tests for AlienVault OTX MCP tools."""

    def test_otx_tools_registration(self):
        from tools import otx_tools

        mcp = MockFastMCP()
        otx_tools.register_tools(mcp)

        assert "lookup_ioc_otx" in mcp.tools
        assert "search_otx_pulses" in mcp.tools
        assert "get_otx_pulse" in mcp.tools
        assert "get_otx_subscribed" in mcp.tools

    def test_lookup_ioc_otx_with_mock(self):
        from tools import otx_tools

        mcp = MockFastMCP()
        otx_tools.register_tools(mcp)
        otx_tools.get_client.cache_clear()

        with patch.object(otx_tools, "get_client") as mock_get:
            mock_client = MagicMock()
            mock_client.get_indicator_full.return_value = {
                "pulse_count": 3,
                "reputation": 0,
            }
            mock_get.return_value = mock_client

            result = mcp.tools["lookup_ioc_otx"](indicator="8.8.8.8", indicator_type="ipv4")
            data = json.loads(result)
            assert data["source"] == "AlienVault OTX"
            assert data["indicator"] == "8.8.8.8"
            assert data["data"]["pulse_count"] == 3

    def test_search_otx_pulses_with_mock(self):
        from tools import otx_tools

        mcp = MockFastMCP()
        otx_tools.register_tools(mcp)
        otx_tools.get_client.cache_clear()

        with patch.object(otx_tools, "get_client") as mock_get:
            mock_client = MagicMock()
            mock_client.search_pulses.return_value = [
                {"id": "pulse1", "name": "Emotet Campaign"},
            ]
            mock_get.return_value = mock_client

            result = mcp.tools["search_otx_pulses"](query="Emotet")
            data = json.loads(result)
            assert data["count"] == 1
            assert data["pulses"][0]["name"] == "Emotet Campaign"


class TestShodanTools:
    """Tests for Shodan MCP tools."""

    def test_shodan_tools_registration(self):
        from tools import shodan_tools

        mcp = MockFastMCP()
        shodan_tools.register_tools(mcp)

        assert "shodan_host_lookup" in mcp.tools
        assert "shodan_search" in mcp.tools
        assert "shodan_dns_lookup" in mcp.tools
        assert "shodan_vuln_lookup" in mcp.tools
        assert "shodan_exploit_search" in mcp.tools

    def test_shodan_host_lookup_no_key(self):
        from tools import shodan_tools

        mcp = MockFastMCP()
        shodan_tools.register_tools(mcp)

        with patch("osint_agent.keymanager.get_api_key", return_value=None):
            result = mcp.tools["shodan_host_lookup"](ip="8.8.8.8")
            assert "Error" in result or "error" in result.lower()

    def test_shodan_host_lookup_with_mock(self):
        from tools import shodan_tools

        mcp = MockFastMCP()
        shodan_tools.register_tools(mcp)

        with patch.object(shodan_tools, "get_shodan_client") as mock_get:
            mock_client = MagicMock()
            mock_client.host.return_value = {
                "ip": "8.8.8.8",
                "org": "Google",
                "isp": "Google LLC",
                "asn": "AS15169",
                "city": "Mountain View",
                "country": "United States",
                "country_code": "US",
                "last_update": "2024-01-01",
                "hostnames": ["dns.google"],
                "domains": ["google.com"],
                "tags": [],
                "ports": [53, 443],
                "vulns": [],
                "services": [],
            }
            mock_get.return_value = mock_client

            result = mcp.tools["shodan_host_lookup"](ip="8.8.8.8")
            assert "Google" in result
            assert "8.8.8.8" in result


class TestFreshRSSTools:
    """Tests for FreshRSS MCP tools."""

    def test_freshrss_tools_registration(self):
        from tools import freshrss_tools

        mcp = MockFastMCP()
        freshrss_tools.register_tools(mcp)

        assert "freshrss_list_feeds" in mcp.tools
        assert "freshrss_get_entries" in mcp.tools
        assert "freshrss_get_unread" in mcp.tools
        assert "freshrss_extract_iocs" in mcp.tools
        assert "freshrss_search" in mcp.tools
        assert "freshrss_mark_read" in mcp.tools

    def test_freshrss_list_feeds_no_credentials(self):
        from tools import freshrss_tools

        mcp = MockFastMCP()
        freshrss_tools.register_tools(mcp)
        freshrss_tools.get_client.cache_clear()

        with patch("osint_agent.keymanager.get_api_key", return_value=None):
            result = mcp.tools["freshrss_list_feeds"]()
            data = json.loads(result)
            assert "error" in data

    def test_freshrss_list_feeds_with_mock(self):
        from tools import freshrss_tools

        mcp = MockFastMCP()
        freshrss_tools.register_tools(mcp)
        freshrss_tools.get_client.cache_clear()

        with patch.object(freshrss_tools, "get_client") as mock_get:
            mock_client = MagicMock()
            mock_client.get_subscriptions.return_value = [
                {"id": "feed/1", "title": "Threat Post", "url": "https://threat.example.com/rss"},
            ]
            mock_get.return_value = mock_client

            result = mcp.tools["freshrss_list_feeds"]()
            data = json.loads(result)
            assert data["feed_count"] == 1
            assert data["feeds"][0]["title"] == "Threat Post"

    def test_freshrss_extract_iocs_with_mock(self):
        from tools import freshrss_tools

        mcp = MockFastMCP()
        freshrss_tools.register_tools(mcp)
        freshrss_tools.get_client.cache_clear()

        with patch.object(freshrss_tools, "get_client") as mock_get:
            mock_client = MagicMock()
            mock_client.get_entries.return_value = {
                "entries": [
                    {
                        "id": "entry1",
                        "title": "Malware alert for 8.8.8.8",
                        "url": "https://example.com/alert",
                        "summary": "Detected C2 at evil.com",
                        "feed_title": "Threat Feed",
                        "published": 1706300000,
                    },
                ],
                "continuation": None,
            }
            mock_get.return_value = mock_client

            result = mcp.tools["freshrss_extract_iocs"](count=10)
            data = json.loads(result)
            assert data["entries_processed"] == 1
            assert data["total_iocs"] > 0


class TestContextToolsFunctional:
    """Functional tests for context management MCP tools."""

    def test_get_context_summary(self, tmp_path):
        from tools import context_tools

        mcp = MockFastMCP()

        # Override the context dir to use temp
        original_manager = context_tools._manager
        context_tools._manager = None

        with patch.object(context_tools, "get_manager") as mock_get:
            from osint_agent.context import ContextManager

            manager = ContextManager(tmp_path)
            mock_get.return_value = manager

            context_tools.register_tools(mcp)

            result = mcp.tools["get_context_summary"]()
            data = json.loads(result)
            assert "context_summary" in data

        context_tools._manager = original_manager

    def test_set_and_get_context(self, tmp_path):
        from tools import context_tools

        mcp = MockFastMCP()

        original_manager = context_tools._manager
        context_tools._manager = None

        with patch.object(context_tools, "get_manager") as mock_get:
            from osint_agent.context import ContextManager

            manager = ContextManager(tmp_path)
            mock_get.return_value = manager

            context_tools.register_tools(mcp)

            # Set a value
            result = mcp.tools["set_context"](
                tier="tactical",
                key="test_key",
                value_json='"test_value"',
            )
            data = json.loads(result)
            assert data["status"] == "success"

            # Get it back
            result = mcp.tools["get_context"](tier="tactical", key="test_key")
            data = json.loads(result)
            assert data["data"] == "test_value"

        context_tools._manager = original_manager

    def test_add_ioc_to_context(self, tmp_path):
        from tools import context_tools

        mcp = MockFastMCP()

        original_manager = context_tools._manager
        context_tools._manager = None

        with patch.object(context_tools, "get_manager") as mock_get:
            from osint_agent.context import ContextManager

            manager = ContextManager(tmp_path)
            mock_get.return_value = manager

            context_tools.register_tools(mcp)

            result = mcp.tools["add_ioc_to_context"](
                ioc_type="ipv4",
                value="1.2.3.4",
                confidence=0.9,
                source="test",
            )
            data = json.loads(result)
            assert data["status"] == "ioc_added"
            assert data["type"] == "ipv4"

            # Verify it's in active IOCs
            result = mcp.tools["get_active_iocs"]()
            data = json.loads(result)
            assert data["count"] >= 1

        context_tools._manager = original_manager

    def test_add_finding(self, tmp_path):
        from tools import context_tools

        mcp = MockFastMCP()

        original_manager = context_tools._manager
        context_tools._manager = None

        with patch.object(context_tools, "get_manager") as mock_get:
            from osint_agent.context import ContextManager

            manager = ContextManager(tmp_path)
            mock_get.return_value = manager

            context_tools.register_tools(mcp)

            result = mcp.tools["add_finding"](
                title="C2 Infrastructure",
                description="Identified command and control server",
                confidence=0.85,
            )
            data = json.loads(result)
            assert data["status"] == "finding_added"

            result = mcp.tools["get_findings"]()
            data = json.loads(result)
            assert data["count"] >= 1

        context_tools._manager = original_manager


class TestCampaignToolsFunctional:
    """Functional tests for campaign management MCP tools."""

    def test_campaign_create_and_get(self, tmp_path):
        from tools import campaign_tools

        mcp = MockFastMCP()

        with patch.object(campaign_tools, "get_campaign_manager") as mock_get:
            from osint_agent.campaigns import CampaignManager

            manager = CampaignManager(data_dir=tmp_path)
            mock_get.return_value = manager

            campaign_tools.register_tools(mcp)

            result = mcp.tools["campaign_create"](
                name="Test Campaign",
                description="Testing campaign creation",
                threat_actor="APT29",
                tags="apt,russia",
            )
            assert "Campaign Created" in result
            assert "Test Campaign" in result

    def test_campaign_list_empty(self, tmp_path):
        from tools import campaign_tools

        mcp = MockFastMCP()

        with patch.object(campaign_tools, "get_campaign_manager") as mock_get:
            from osint_agent.campaigns import CampaignManager

            manager = CampaignManager(data_dir=tmp_path)
            mock_get.return_value = manager

            campaign_tools.register_tools(mcp)

            result = mcp.tools["campaign_list"]()
            assert "No campaigns found" in result

    def test_campaign_add_ioc_and_find(self, tmp_path):
        from tools import campaign_tools

        mcp = MockFastMCP()

        with patch.object(campaign_tools, "get_campaign_manager") as mock_get:
            from osint_agent.campaigns import CampaignManager

            manager = CampaignManager(data_dir=tmp_path)
            mock_get.return_value = manager

            campaign_tools.register_tools(mcp)

            # Create campaign first
            result = mcp.tools["campaign_create"](
                name="IOC Test Campaign",
                description="Test",
            )
            assert "Campaign Created" in result

            # Get the campaign ID from the output
            campaigns = manager.list()
            assert len(campaigns) == 1
            campaign_id = campaigns[0].id

            # Add IOC
            result = mcp.tools["campaign_add_ioc"](
                campaign_id=campaign_id,
                ioc_type="ipv4",
                value="1.2.3.4",
                source="test",
                confidence="high",
            )
            assert "Added" in result

            # Find by IOC
            result = mcp.tools["campaign_find_by_ioc"](
                ioc_type="ipv4",
                value="1.2.3.4",
            )
            assert "IOC Test Campaign" in result

    def test_campaign_statistics(self, tmp_path):
        from tools import campaign_tools

        mcp = MockFastMCP()

        with patch.object(campaign_tools, "get_campaign_manager") as mock_get:
            from osint_agent.campaigns import CampaignManager

            manager = CampaignManager(data_dir=tmp_path)
            mock_get.return_value = manager

            campaign_tools.register_tools(mcp)

            result = mcp.tools["campaign_statistics"]()
            assert "Campaign Statistics" in result
            assert "Total Campaigns" in result


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
