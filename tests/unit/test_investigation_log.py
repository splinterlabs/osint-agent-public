"""Unit tests for osint_agent.investigation_log."""

import json
from pathlib import Path

import pytest

from osint_agent.investigation_log import InvestigationLogger, _sanitize_filename


class TestSanitizeFilename:
    def test_simple_string(self):
        assert _sanitize_filename("hello") == "hello"

    def test_ip_address(self):
        assert _sanitize_filename("192.168.1.1") == "192.168.1.1"

    def test_cve_id(self):
        assert _sanitize_filename("CVE-2026-24061") == "CVE-2026-24061"

    def test_domain(self):
        assert _sanitize_filename("evil.example.com") == "evil.example.com"

    def test_url_colons_slashes(self):
        result = _sanitize_filename("https://evil.com/path?q=1")
        assert ":" not in result
        assert "/" not in result
        assert "?" not in result

    def test_spaces_replaced(self):
        result = _sanitize_filename("some indicator value")
        assert " " not in result

    def test_consecutive_underscores_collapsed(self):
        result = _sanitize_filename("a::b//c")
        # Each special char becomes _, then collapsed
        assert "__" not in result

    def test_truncation(self):
        long_name = "A" * 200
        result = _sanitize_filename(long_name)
        assert len(result) <= 120

    def test_leading_trailing_underscores_stripped(self):
        result = _sanitize_filename("///test///")
        assert not result.startswith("_")
        assert not result.endswith("_")


class TestInvestigationLogger:
    @pytest.fixture()
    def logger(self, tmp_path: Path) -> InvestigationLogger:
        return InvestigationLogger("CVE-2026-24061", log_dir=tmp_path)

    def test_log_file_created_in_directory(self, logger: InvestigationLogger, tmp_path: Path):
        assert logger.path.parent == tmp_path

    def test_filename_contains_indicator(self, logger: InvestigationLogger):
        assert "CVE-2026-24061" in logger.filename

    def test_filename_starts_with_prefix(self, logger: InvestigationLogger):
        assert logger.filename.startswith("investigate_")

    def test_filename_ends_with_jsonl(self, logger: InvestigationLogger):
        assert logger.filename.endswith(".jsonl")

    def test_write_header(self, logger: InvestigationLogger):
        logger.write_header(
            indicator="CVE-2026-24061",
            indicator_type="CVE",
            investigation_name="test-investigation",
        )

        entries = logger.read_log()
        assert len(entries) == 1
        assert entries[0]["event"] == "investigation_start"
        assert entries[0]["indicator"] == "CVE-2026-24061"
        assert entries[0]["indicator_type"] == "CVE"
        assert entries[0]["investigation_name"] == "test-investigation"
        assert "timestamp" in entries[0]

    def test_log_step_returns_incrementing_numbers(self, logger: InvestigationLogger):
        n1 = logger.log_step("NVD", "CVE-2026-24061", "checked", "CVSS 9.8")
        n2 = logger.log_step("KEV", "CVE-2026-24061", "checked", "In KEV")
        n3 = logger.log_step("Shodan", "CVE-2026-24061", "error", "Timeout")

        assert n1 == 1
        assert n2 == 2
        assert n3 == 3

    def test_log_step_persists_data(self, logger: InvestigationLogger):
        raw = {"cvss": 9.8, "description": "Auth bypass"}
        logger.log_step(
            source="NVD",
            indicator="CVE-2026-24061",
            status="checked",
            summary="CVSS 9.8, auth bypass",
            raw_result=raw,
        )

        entries = logger.read_log()
        assert len(entries) == 1
        entry = entries[0]
        assert entry["event"] == "enrichment_step"
        assert entry["step"] == 1
        assert entry["source"] == "NVD"
        assert entry["status"] == "checked"
        assert entry["summary"] == "CVSS 9.8, auth bypass"
        assert entry["raw_result"]["cvss"] == 9.8
        assert "timestamp" in entry

    def test_log_step_handles_none_raw_result(self, logger: InvestigationLogger):
        logger.log_step("NVD", "CVE-2026-24061", "checked", "No data")
        entries = logger.read_log()
        assert entries[0]["raw_result"] is None

    def test_write_conclusion(self, logger: InvestigationLogger):
        logger.log_step("NVD", "CVE-2026-24061", "checked", "CVSS 9.8")
        logger.log_step("KEV", "CVE-2026-24061", "checked", "In KEV")

        coverage = [
            {"source": "NVD", "status": "Checked", "finding": "CVSS 9.8"},
            {"source": "KEV", "status": "Checked", "finding": "In KEV"},
        ]
        logger.write_conclusion(
            verdict="Malicious",
            confidence="High",
            risk_level="Critical",
            summary="Critical auth bypass actively exploited.",
            coverage=coverage,
        )

        entries = logger.read_log()
        assert len(entries) == 3
        conclusion = entries[2]
        assert conclusion["event"] == "investigation_conclusion"
        assert conclusion["verdict"] == "Malicious"
        assert conclusion["confidence"] == "High"
        assert conclusion["risk_level"] == "Critical"
        assert conclusion["total_steps"] == 2
        assert len(conclusion["coverage"]) == 2

    def test_write_conclusion_default_coverage(self, logger: InvestigationLogger):
        logger.write_conclusion(
            verdict="Inconclusive",
            confidence="Low",
            risk_level="Info",
            summary="No data.",
        )
        entries = logger.read_log()
        assert entries[0]["coverage"] == []

    def test_read_log_empty_file(self, logger: InvestigationLogger):
        # No writes yet — file doesn't exist
        assert logger.read_log() == []

    def test_full_lifecycle(self, logger: InvestigationLogger):
        """Header -> steps -> conclusion -> read back all."""
        logger.write_header("CVE-2026-24061", "CVE", "lifecycle-test")
        logger.log_step("NVD", "CVE-2026-24061", "checked", "CVSS 9.8", {"score": 9.8})
        logger.log_step("KEV", "CVE-2026-24061", "checked", "In KEV", {"in_kev": True})
        logger.log_step("Shodan", "CVE-2026-24061", "error", "Timeout")
        logger.write_conclusion("Malicious", "High", "Critical", "Active exploitation.")

        entries = logger.read_log()
        assert len(entries) == 5
        assert entries[0]["event"] == "investigation_start"
        assert entries[1]["event"] == "enrichment_step"
        assert entries[1]["step"] == 1
        assert entries[2]["step"] == 2
        assert entries[3]["step"] == 3
        assert entries[3]["status"] == "error"
        assert entries[4]["event"] == "investigation_conclusion"
        assert entries[4]["total_steps"] == 3

    def test_directory_created_if_missing(self, tmp_path: Path):
        nested = tmp_path / "deep" / "nested" / "dir"
        log = InvestigationLogger("test", log_dir=nested)
        log.write_header("test", "domain")
        assert nested.exists()
        assert log.read_log()[0]["event"] == "investigation_start"

    def test_special_characters_in_indicator(self, tmp_path: Path):
        log = InvestigationLogger("https://evil.com/path?q=1&r=2", log_dir=tmp_path)
        assert log.path.exists() is False  # Not created until first write
        log.write_header("https://evil.com/path?q=1&r=2", "URL")
        assert log.path.exists()
        # Verify filename is safe
        assert "/" not in log.filename
        assert "?" not in log.filename
        assert "&" not in log.filename
