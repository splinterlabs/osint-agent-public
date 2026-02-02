"""Unit tests for API clients."""

import pytest
import responses
from responses import matchers

from osint_agent.clients.base import (
    APIError,
    APITimeoutError,
    BaseClient,
    ProxyConfig,
    RateLimitError,
)
from osint_agent.clients.nvd import NVDClient
from osint_agent.clients.cisa_kev import CISAKEVClient


class TestProxyConfig:
    """Tests for proxy configuration."""

    def test_proxy_disabled(self):
        config = ProxyConfig(enabled=False, http_proxy="http://proxy:8080")
        assert config.get_proxies() == {}

    def test_proxy_from_explicit_config(self):
        config = ProxyConfig(
            http_proxy="http://proxy:8080",
            https_proxy="https://proxy:8443",
        )
        proxies = config.get_proxies()
        assert proxies["http"] == "http://proxy:8080"
        assert proxies["https"] == "https://proxy:8443"

    def test_proxy_bypass_exact_match(self):
        config = ProxyConfig(no_proxy=["localhost", "internal.corp"])
        assert config.should_bypass("http://localhost/api") is True
        assert config.should_bypass("http://internal.corp/api") is True
        assert config.should_bypass("http://external.com/api") is False

    def test_proxy_bypass_suffix_match(self):
        config = ProxyConfig(no_proxy=[".internal.corp"])
        assert config.should_bypass("http://api.internal.corp/v1") is True
        assert config.should_bypass("http://internal.corp/v1") is True
        assert config.should_bypass("http://external.com/v1") is False

    def test_proxy_from_dict(self):
        config = ProxyConfig.from_dict({
            "http_proxy": "http://proxy:8080",
            "enabled": True,
        })
        assert config.http_proxy == "http://proxy:8080"
        assert config.enabled is True


class TestBaseClient:
    """Tests for base client functionality."""

    @responses.activate
    def test_successful_get_request(self):
        responses.add(
            responses.GET,
            "https://api.example.com/test",
            json={"status": "ok"},
            status=200,
        )

        client = BaseClient()
        client.BASE_URL = "https://api.example.com"
        result = client.get("/test")

        assert result == {"status": "ok"}

    @responses.activate
    def test_rate_limit_error(self):
        responses.add(
            responses.GET,
            "https://api.example.com/test",
            status=429,
            headers={"Retry-After": "60"},
        )

        client = BaseClient()
        client.BASE_URL = "https://api.example.com"

        with pytest.raises(RateLimitError) as exc_info:
            client.get("/test")

        assert exc_info.value.retry_after == 60

    @responses.activate
    def test_retry_on_failure(self):
        import requests as req_lib

        # First two requests fail, third succeeds
        responses.add(
            responses.GET,
            "https://api.example.com/test",
            body=req_lib.exceptions.ConnectionError("Connection failed"),
        )
        responses.add(
            responses.GET,
            "https://api.example.com/test",
            body=req_lib.exceptions.ConnectionError("Connection failed"),
        )
        responses.add(
            responses.GET,
            "https://api.example.com/test",
            json={"status": "ok"},
            status=200,
        )

        client = BaseClient()
        client.BASE_URL = "https://api.example.com"
        client.BACKOFF_BASE = 0.01  # Fast backoff for tests
        result = client.get("/test")

        assert result == {"status": "ok"}
        assert len(responses.calls) == 3

    @responses.activate
    def test_max_retries_exceeded(self):
        import requests as req_lib

        # All requests fail
        for _ in range(3):
            responses.add(
                responses.GET,
                "https://api.example.com/test",
                body=req_lib.exceptions.ConnectionError("Connection failed"),
            )

        client = BaseClient()
        client.BASE_URL = "https://api.example.com"
        client.BACKOFF_BASE = 0.01

        with pytest.raises(APIError):
            client.get("/test")

    @responses.activate
    def test_http_error_handling(self):
        responses.add(
            responses.GET,
            "https://api.example.com/test",
            status=500,
        )

        client = BaseClient()
        client.BASE_URL = "https://api.example.com"
        client.MAX_RETRIES = 1

        with pytest.raises(APIError):
            client.get("/test")


class TestNVDClient:
    """Tests for NVD client."""

    @responses.activate
    def test_lookup_cve_found(self):
        mock_response = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [
                        {"lang": "en", "value": "Test vulnerability"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseSeverity": "CRITICAL",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                            }
                        }]
                    },
                    "weaknesses": [],
                    "configurations": [],
                    "references": [],
                    "published": "2024-01-15T00:00:00.000",
                    "lastModified": "2024-01-16T00:00:00.000",
                }
            }]
        }

        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json=mock_response,
            status=200,
        )

        client = NVDClient()
        result = client.lookup("CVE-2024-1234")

        assert result["id"] == "CVE-2024-1234"
        assert result["cvss_v3_score"] == 9.8
        assert result["description"] == "Test vulnerability"

    @responses.activate
    def test_lookup_cve_not_found(self):
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json={"vulnerabilities": []},
            status=200,
        )

        client = NVDClient()
        result = client.lookup("CVE-2024-99999")

        assert "error" in result

    @responses.activate
    def test_api_key_header(self):
        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json={"vulnerabilities": []},
            status=200,
        )

        client = NVDClient(api_key="test-api-key")
        client.lookup("CVE-2024-1234")

        assert responses.calls[0].request.headers.get("apiKey") == "test-api-key"

    @responses.activate
    def test_get_critical_cves(self):
        mock_response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "descriptions": [{"lang": "en", "value": "Critical vuln"}],
                        "metrics": {
                            "cvssMetricV31": [{
                                "cvssData": {"baseScore": 9.8, "vectorString": "", "baseSeverity": "CRITICAL"}
                            }]
                        },
                        "weaknesses": [],
                        "configurations": [],
                        "references": [],
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2024-0002",
                        "descriptions": [{"lang": "en", "value": "High vuln"}],
                        "metrics": {
                            "cvssMetricV31": [{
                                "cvssData": {"baseScore": 7.5, "vectorString": "", "baseSeverity": "HIGH"}
                            }]
                        },
                        "weaknesses": [],
                        "configurations": [],
                        "references": [],
                    }
                },
            ]
        }

        responses.add(
            responses.GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json=mock_response,
            status=200,
        )

        client = NVDClient()
        results = client.get_critical(cvss_min=8.0, days=7)

        # Only the 9.8 score CVE should be returned (>= 8.0)
        assert len(results) == 1
        assert results[0]["id"] == "CVE-2024-0001"


class TestCISAKEVClient:
    """Tests for CISA KEV client."""

    @responses.activate
    def test_lookup_found(self):
        mock_catalog = {
            "catalogVersion": "2024.01.15",
            "dateReleased": "2024-01-15",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-1234",
                    "vendorProject": "TestVendor",
                    "product": "TestProduct",
                    "vulnerabilityName": "Test Vulnerability",
                    "dateAdded": "2024-01-10",
                    "shortDescription": "A test vulnerability",
                    "requiredAction": "Apply patches",
                    "dueDate": "2024-02-10",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "",
                }
            ]
        }

        responses.add(
            responses.GET,
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            json=mock_catalog,
            status=200,
        )

        client = CISAKEVClient()
        result = client.lookup("CVE-2024-1234")

        assert result is not None
        assert result["cve_id"] == "CVE-2024-1234"
        assert result["vendor"] == "TestVendor"
        assert result["known_ransomware_use"] == "Known"

    @responses.activate
    def test_lookup_not_found(self):
        mock_catalog = {
            "catalogVersion": "2024.01.15",
            "vulnerabilities": []
        }

        responses.add(
            responses.GET,
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            json=mock_catalog,
            status=200,
        )

        client = CISAKEVClient()
        result = client.lookup("CVE-2024-99999")

        assert result is None

    @responses.activate
    def test_is_exploited(self):
        mock_catalog = {
            "vulnerabilities": [
                {"cveID": "CVE-2024-1234", "vendorProject": "Test", "product": "Test",
                 "vulnerabilityName": "", "dateAdded": "", "shortDescription": "",
                 "requiredAction": "", "dueDate": ""}
            ]
        }

        responses.add(
            responses.GET,
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            json=mock_catalog,
            status=200,
        )

        client = CISAKEVClient()
        assert client.is_exploited("CVE-2024-1234") is True
        assert client.is_exploited("CVE-2024-9999") is False

    @responses.activate
    def test_caching(self):
        mock_catalog = {"vulnerabilities": []}

        responses.add(
            responses.GET,
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            json=mock_catalog,
            status=200,
        )

        client = CISAKEVClient()
        client.lookup("CVE-2024-1234")
        client.lookup("CVE-2024-5678")

        # Should only make one request due to caching
        assert len(responses.calls) == 1

    @responses.activate
    def test_get_by_vendor(self):
        mock_catalog = {
            "vulnerabilities": [
                {"cveID": "CVE-2024-0001", "vendorProject": "Microsoft", "product": "Windows",
                 "vulnerabilityName": "", "dateAdded": "", "shortDescription": "",
                 "requiredAction": "", "dueDate": ""},
                {"cveID": "CVE-2024-0002", "vendorProject": "Apple", "product": "iOS",
                 "vulnerabilityName": "", "dateAdded": "", "shortDescription": "",
                 "requiredAction": "", "dueDate": ""},
                {"cveID": "CVE-2024-0003", "vendorProject": "Microsoft", "product": "Office",
                 "vulnerabilityName": "", "dateAdded": "", "shortDescription": "",
                 "requiredAction": "", "dueDate": ""},
            ]
        }

        responses.add(
            responses.GET,
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            json=mock_catalog,
            status=200,
        )

        client = CISAKEVClient()
        results = client.get_by_vendor("microsoft")

        assert len(results) == 2
        assert all(r["vendor"] == "Microsoft" for r in results)

    @responses.activate
    def test_get_stats(self):
        mock_catalog = {
            "catalogVersion": "2024.01.15",
            "dateReleased": "2024-01-15",
            "vulnerabilities": [
                {"cveID": "CVE-1", "vendorProject": "Microsoft", "knownRansomwareCampaignUse": "Known",
                 "product": "", "vulnerabilityName": "", "dateAdded": "", "shortDescription": "",
                 "requiredAction": "", "dueDate": ""},
                {"cveID": "CVE-2", "vendorProject": "Microsoft", "knownRansomwareCampaignUse": "Unknown",
                 "product": "", "vulnerabilityName": "", "dateAdded": "", "shortDescription": "",
                 "requiredAction": "", "dueDate": ""},
                {"cveID": "CVE-3", "vendorProject": "Apple", "knownRansomwareCampaignUse": "Known",
                 "product": "", "vulnerabilityName": "", "dateAdded": "", "shortDescription": "",
                 "requiredAction": "", "dueDate": ""},
            ]
        }

        responses.add(
            responses.GET,
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            json=mock_catalog,
            status=200,
        )

        client = CISAKEVClient()
        stats = client.get_stats()

        assert stats["total_vulnerabilities"] == 3
        assert stats["ransomware_associated"] == 2
        assert stats["top_vendors"]["Microsoft"] == 2
        assert stats["top_vendors"]["Apple"] == 1
