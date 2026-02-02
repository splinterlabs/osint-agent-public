"""Unit tests for FreshRSS client."""

from unittest.mock import patch

import pytest
import responses

from osint_agent.clients.base import APIError
from osint_agent.clients.freshrss import FreshRSSClient


class TestFreshRSSAuthentication:
    """Tests for FreshRSS authentication."""

    @responses.activate
    @patch("osint_agent.clients.freshrss.FreshRSSClient._get_password")
    def test_authenticate_success(self, mock_get_password):
        mock_get_password.return_value = "testpass"

        responses.add(
            responses.POST,
            "https://rss.example.com/accounts/ClientLogin",
            body="SID=test_sid\nAuth=test_auth_token\n",
            status=200,
        )

        client = FreshRSSClient(
            base_url="https://rss.example.com",
            username="testuser",
            password="testpass",
        )
        result = client.authenticate()

        assert result is True
        assert client._auth_token == "test_auth_token"

    @responses.activate
    @patch("osint_agent.clients.freshrss.FreshRSSClient._get_password")
    def test_authenticate_failure(self, mock_get_password):
        mock_get_password.return_value = "wrongpass"

        responses.add(
            responses.POST,
            "https://rss.example.com/accounts/ClientLogin",
            status=401,
        )

        client = FreshRSSClient(
            base_url="https://rss.example.com",
            username="testuser",
            password="wrongpass",
        )

        with pytest.raises(APIError):
            client.authenticate()

    @responses.activate
    @patch("osint_agent.clients.freshrss.FreshRSSClient._get_password")
    def test_authenticate_missing_token(self, mock_get_password):
        mock_get_password.return_value = "testpass"

        responses.add(
            responses.POST,
            "https://rss.example.com/accounts/ClientLogin",
            body="SID=test_sid\n",  # Missing Auth token
            status=200,
        )

        client = FreshRSSClient(
            base_url="https://rss.example.com",
            username="testuser",
            password="testpass",
        )

        with pytest.raises(APIError) as exc_info:
            client.authenticate()

        assert "missing Auth token" in str(exc_info.value)

    def test_base_url_trailing_slash_stripped(self):
        client = FreshRSSClient(
            base_url="https://rss.example.com/",
            username="testuser",
            password="testpass",
        )
        assert client.base_url == "https://rss.example.com"


class TestFreshRSSSubscriptions:
    """Tests for FreshRSS subscription listing."""

    @responses.activate
    @patch("osint_agent.clients.freshrss.FreshRSSClient._get_password")
    def test_get_subscriptions(self, mock_get_password):
        mock_get_password.return_value = "testpass"

        # Auth endpoint
        responses.add(
            responses.POST,
            "https://rss.example.com/accounts/ClientLogin",
            body="SID=test_sid\nAuth=test_auth\n",
            status=200,
        )

        # Subscriptions endpoint
        responses.add(
            responses.GET,
            "https://rss.example.com/reader/api/0/subscription/list",
            json={
                "subscriptions": [
                    {
                        "id": "feed/1",
                        "title": "Security News",
                        "url": "https://security.example.com/feed",
                        "htmlUrl": "https://security.example.com",
                        "iconUrl": "https://security.example.com/icon.png",
                        "categories": [{"id": "cat/1", "label": "Security"}],
                    },
                    {
                        "id": "feed/2",
                        "title": "CVE Updates",
                        "url": "https://cve.example.com/rss",
                        "htmlUrl": "https://cve.example.com",
                        "categories": [],
                    },
                ]
            },
            status=200,
        )

        client = FreshRSSClient(
            base_url="https://rss.example.com",
            username="testuser",
            password="testpass",
        )
        subs = client.get_subscriptions()

        assert len(subs) == 2
        assert subs[0]["id"] == "feed/1"
        assert subs[0]["title"] == "Security News"
        assert subs[0]["categories"][0]["label"] == "Security"
        assert subs[1]["id"] == "feed/2"


class TestFreshRSSEntries:
    """Tests for FreshRSS entry fetching."""

    @responses.activate
    @patch("osint_agent.clients.freshrss.FreshRSSClient._get_password")
    def test_get_entries_all_feeds(self, mock_get_password):
        mock_get_password.return_value = "testpass"
        # Auth endpoint
        responses.add(
            responses.POST,
            "https://rss.example.com/accounts/ClientLogin",
            body="Auth=test_auth\n",
            status=200,
        )

        # Entries endpoint
        responses.add(
            responses.GET,
            "https://rss.example.com/reader/api/0/stream/contents/user%2F-%2Fstate%2Fcom.google%2Freading-list",
            json={
                "items": [
                    {
                        "id": "entry/1",
                        "title": "Critical CVE Alert",
                        "published": 1706000000,
                        "canonical": [{"href": "https://example.com/alert"}],
                        "summary": {"content": "Critical vulnerability discovered"},
                        "origin": {
                            "streamId": "feed/1",
                            "title": "Security News",
                        },
                        "categories": [],
                    },
                ],
                "continuation": "next_page_token",
            },
            status=200,
        )

        client = FreshRSSClient(
            base_url="https://rss.example.com",
            username="testuser",
            password="testpass",
        )
        result = client.get_entries(count=20)

        assert len(result["entries"]) == 1
        assert result["entries"][0]["id"] == "entry/1"
        assert result["entries"][0]["title"] == "Critical CVE Alert"
        assert result["entries"][0]["url"] == "https://example.com/alert"
        assert result["continuation"] == "next_page_token"

    @responses.activate
    @patch("osint_agent.clients.freshrss.FreshRSSClient._get_password")
    def test_get_entries_specific_feed(self, mock_get_password):
        mock_get_password.return_value = "testpass"
        # Auth endpoint
        responses.add(
            responses.POST,
            "https://rss.example.com/accounts/ClientLogin",
            body="Auth=test_auth\n",
            status=200,
        )

        # Entries endpoint for specific feed
        responses.add(
            responses.GET,
            "https://rss.example.com/reader/api/0/stream/contents/feed%2F1",
            json={"items": [], "continuation": None},
            status=200,
        )

        client = FreshRSSClient(
            base_url="https://rss.example.com",
            username="testuser",
            password="testpass",
        )
        result = client.get_entries(feed_id="feed/1", count=10)

        assert result["entries"] == []
        assert result["continuation"] is None

    @responses.activate
    @patch("osint_agent.clients.freshrss.FreshRSSClient._get_password")
    def test_get_unread_entries(self, mock_get_password):
        mock_get_password.return_value = "testpass"
        # Auth endpoint
        responses.add(
            responses.POST,
            "https://rss.example.com/accounts/ClientLogin",
            body="Auth=test_auth\n",
            status=200,
        )

        # Entries endpoint with unread filter
        responses.add(
            responses.GET,
            "https://rss.example.com/reader/api/0/stream/contents/user%2F-%2Fstate%2Fcom.google%2Freading-list",
            json={
                "items": [
                    {
                        "id": "entry/2",
                        "title": "Unread Alert",
                        "published": 1706100000,
                        "canonical": [{"href": "https://example.com/unread"}],
                        "summary": {"content": "New threat detected"},
                        "origin": {"streamId": "feed/1", "title": "Alerts"},
                        "categories": [],
                    },
                ],
            },
            status=200,
        )

        client = FreshRSSClient(
            base_url="https://rss.example.com",
            username="testuser",
            password="testpass",
        )
        entries = client.get_unread_entries(count=50)

        assert len(entries) == 1
        assert entries[0]["title"] == "Unread Alert"


class TestFreshRSSMarkRead:
    """Tests for marking entries as read."""

    @responses.activate
    @patch("osint_agent.clients.freshrss.FreshRSSClient._get_password")
    def test_mark_read_success(self, mock_get_password):
        mock_get_password.return_value = "testpass"
        # Auth endpoint
        responses.add(
            responses.POST,
            "https://rss.example.com/accounts/ClientLogin",
            body="Auth=test_auth\n",
            status=200,
        )

        # Mark read endpoint
        responses.add(
            responses.POST,
            "https://rss.example.com/reader/api/0/edit-tag",
            body="OK",
            status=200,
        )

        client = FreshRSSClient(
            base_url="https://rss.example.com",
            username="testuser",
            password="testpass",
        )
        result = client.mark_read(["entry/1", "entry/2"])

        assert result is True

    @responses.activate
    def test_mark_read_empty_list(self):
        client = FreshRSSClient(
            base_url="https://rss.example.com",
            username="testuser",
            password="testpass",
        )
        result = client.mark_read([])

        assert result is True
        # No HTTP calls should be made for empty list


class TestFreshRSSSearch:
    """Tests for FreshRSS search functionality."""

    @responses.activate
    @patch("osint_agent.clients.freshrss.FreshRSSClient._get_password")
    def test_search_server_side(self, mock_get_password):
        mock_get_password.return_value = "testpass"
        # Auth endpoint
        responses.add(
            responses.POST,
            "https://rss.example.com/accounts/ClientLogin",
            body="Auth=test_auth\n",
            status=200,
        )

        # Search endpoint
        responses.add(
            responses.GET,
            "https://rss.example.com/reader/api/0/stream/contents",
            json={
                "items": [
                    {
                        "id": "entry/search1",
                        "title": "CVE-2024-1234 Analysis",
                        "published": 1706000000,
                        "canonical": [{"href": "https://example.com/cve"}],
                        "summary": {"content": "Analysis of CVE-2024-1234"},
                        "origin": {"streamId": "feed/1", "title": "CVE Feed"},
                        "categories": [],
                    },
                ],
            },
            status=200,
        )

        client = FreshRSSClient(
            base_url="https://rss.example.com",
            username="testuser",
            password="testpass",
        )
        results = client.search("CVE-2024-1234", count=20)

        assert len(results) == 1
        assert "CVE-2024-1234" in results[0]["title"]


class TestFreshRSSEntryParsing:
    """Tests for entry parsing logic."""

    @responses.activate
    @patch("osint_agent.clients.freshrss.FreshRSSClient._get_password")
    def test_parse_entry_with_content_field(self, mock_get_password):
        mock_get_password.return_value = "testpass"
        # Auth endpoint
        responses.add(
            responses.POST,
            "https://rss.example.com/accounts/ClientLogin",
            body="Auth=test_auth\n",
            status=200,
        )

        # Entry with content instead of summary
        responses.add(
            responses.GET,
            "https://rss.example.com/reader/api/0/stream/contents/user%2F-%2Fstate%2Fcom.google%2Freading-list",
            json={
                "items": [
                    {
                        "id": "entry/1",
                        "title": "Test Entry",
                        "published": 1706000000,
                        "updated": 1706100000,
                        "author": "Security Team",
                        "alternate": [{"href": "https://example.com/alt"}],
                        "content": {"content": "Full content here"},
                        "origin": {"streamId": "feed/1", "title": "Test Feed"},
                        "categories": [{"label": "security"}, {"label": "alert"}],
                    },
                ],
            },
            status=200,
        )

        client = FreshRSSClient(
            base_url="https://rss.example.com",
            username="testuser",
            password="testpass",
        )
        result = client.get_entries()

        entry = result["entries"][0]
        assert entry["summary"] == "Full content here"
        assert entry["url"] == "https://example.com/alt"
        assert entry["author"] == "Security Team"
        assert entry["updated"] == 1706100000
        assert "security" in entry["categories"]
        assert "alert" in entry["categories"]

    @responses.activate
    @patch("osint_agent.clients.freshrss.FreshRSSClient._get_password")
    def test_parse_entry_with_missing_fields(self, mock_get_password):
        mock_get_password.return_value = "testpass"
        # Auth endpoint
        responses.add(
            responses.POST,
            "https://rss.example.com/accounts/ClientLogin",
            body="Auth=test_auth\n",
            status=200,
        )

        # Minimal entry with missing optional fields
        responses.add(
            responses.GET,
            "https://rss.example.com/reader/api/0/stream/contents/user%2F-%2Fstate%2Fcom.google%2Freading-list",
            json={
                "items": [
                    {
                        "id": "entry/minimal",
                        "title": "Minimal Entry",
                        "published": 1706000000,
                    },
                ],
            },
            status=200,
        )

        client = FreshRSSClient(
            base_url="https://rss.example.com",
            username="testuser",
            password="testpass",
        )
        result = client.get_entries()

        entry = result["entries"][0]
        assert entry["id"] == "entry/minimal"
        assert entry["title"] == "Minimal Entry"
        assert entry["url"] == ""
        assert entry["summary"] == ""
        assert entry["author"] == ""
        assert entry["feed_id"] == ""
        assert entry["categories"] == []


class TestFreshRSSHeaders:
    """Tests for HTTP header handling."""

    @responses.activate
    @patch("osint_agent.clients.freshrss.FreshRSSClient._get_password")
    def test_auth_header_included(self, mock_get_password):
        mock_get_password.return_value = "testpass"
        # Auth endpoint
        responses.add(
            responses.POST,
            "https://rss.example.com/accounts/ClientLogin",
            body="Auth=my_secret_token\n",
            status=200,
        )

        # Subscriptions endpoint
        responses.add(
            responses.GET,
            "https://rss.example.com/reader/api/0/subscription/list",
            json={"subscriptions": []},
            status=200,
        )

        client = FreshRSSClient(
            base_url="https://rss.example.com",
            username="testuser",
            password="testpass",
        )
        client.get_subscriptions()

        # Check that the auth header was included in the subscription request
        sub_request = responses.calls[1].request
        assert "Authorization" in sub_request.headers
        assert "GoogleLogin auth=my_secret_token" in sub_request.headers["Authorization"]
