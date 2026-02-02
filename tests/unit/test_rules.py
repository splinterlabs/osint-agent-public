"""Unit tests for YARA and Sigma rule generation."""

from osint_agent.rules import (
    _escape_yara_string,
    _generate_uuid_from_title,
    generate_sigma_dns_rule,
    generate_sigma_firewall_rule,
    generate_sigma_rule,
    generate_yara_rule,
)


class TestEscapeYaraString:
    """Tests for YARA string escaping."""

    def test_escape_backslash(self):
        assert _escape_yara_string("C:\\Windows") == "C:\\\\Windows"

    def test_escape_double_quote(self):
        assert _escape_yara_string('say "hello"') == 'say \\"hello\\"'

    def test_escape_newline(self):
        assert _escape_yara_string("line1\nline2") == "line1\\nline2"

    def test_escape_combined(self):
        assert _escape_yara_string('C:\\path\n"x"') == 'C:\\\\path\\n\\"x\\"'

    def test_no_escape_needed(self):
        assert _escape_yara_string("simple text") == "simple text"


class TestGenerateUUID:
    """Tests for deterministic UUID generation."""

    def test_deterministic(self):
        id1 = _generate_uuid_from_title("Test Rule")
        id2 = _generate_uuid_from_title("Test Rule")
        assert id1 == id2

    def test_different_titles_different_ids(self):
        id1 = _generate_uuid_from_title("Rule A")
        id2 = _generate_uuid_from_title("Rule B")
        assert id1 != id2

    def test_uuid_format(self):
        result = _generate_uuid_from_title("Test Rule")
        parts = result.split("-")
        assert len(parts) == 5
        assert len(parts[0]) == 8
        assert len(parts[1]) == 4
        assert len(parts[2]) == 4
        assert len(parts[3]) == 4
        assert len(parts[4]) == 12


class TestGenerateYaraRule:
    """Tests for YARA rule generation."""

    def test_basic_hash_rule(self):
        rule = generate_yara_rule(
            name="test_malware",
            hashes=[{"type": "sha256", "value": "a" * 64}],
            description="Test rule",
        )
        assert "rule test_malware" in rule
        assert 'import "hash"' in rule
        assert "hash.sha256(0, filesize)" in rule
        assert "a" * 64 in rule
        assert 'description = "Test rule"' in rule

    def test_multiple_hash_types(self):
        rule = generate_yara_rule(
            name="multi_hash",
            hashes=[
                {"type": "md5", "value": "b" * 32},
                {"type": "sha1", "value": "c" * 40},
                {"type": "sha256", "value": "d" * 64},
            ],
        )
        assert "hash.md5(0, filesize)" in rule
        assert "hash.sha1(0, filesize)" in rule
        assert "hash.sha256(0, filesize)" in rule
        assert " or " in rule

    def test_name_sanitization(self):
        rule = generate_yara_rule(
            name="CVE-2024-1234 Exploit!",
            hashes=[{"type": "md5", "value": "a" * 32}],
        )
        assert "rule CVE_2024_1234_Exploit_" in rule

    def test_name_starting_with_digit(self):
        rule = generate_yara_rule(
            name="123_bad",
            hashes=[{"type": "md5", "value": "a" * 32}],
        )
        assert "rule rule_123_bad" in rule

    def test_with_tags(self):
        rule = generate_yara_rule(
            name="tagged_rule",
            hashes=[{"type": "md5", "value": "a" * 32}],
            tags=["malware", "trojan"],
        )
        assert "tagged_rule : malware trojan" in rule
        assert 'tags = "malware, trojan"' in rule

    def test_with_string_patterns(self):
        rule = generate_yara_rule(
            name="string_rule",
            hashes=[],
            strings=["MZ", "This program"],
        )
        assert '$s0 = "MZ"' in rule
        assert '$s1 = "This program"' in rule
        assert "any of ($s*)" in rule

    def test_invalid_hash_length_ignored(self):
        rule = generate_yara_rule(
            name="bad_hash",
            hashes=[{"type": "md5", "value": "tooshort"}],
        )
        # Invalid hash should not produce a hash condition
        assert "hash.md5" not in rule
        assert "condition:" in rule
        assert "false" in rule

    def test_empty_hashes_and_no_strings(self):
        rule = generate_yara_rule(name="empty_rule", hashes=[])
        assert "condition:" in rule
        assert "false" in rule

    def test_author_in_meta(self):
        rule = generate_yara_rule(
            name="authored",
            hashes=[{"type": "md5", "value": "a" * 32}],
            author="Security Team",
        )
        assert 'author = "Security Team"' in rule

    def test_date_in_meta(self):
        rule = generate_yara_rule(
            name="dated",
            hashes=[{"type": "md5", "value": "a" * 32}],
        )
        assert "date = " in rule


class TestGenerateSigmaRule:
    """Tests for generic Sigma rule generation."""

    def test_basic_ip_rule(self):
        rule = generate_sigma_rule(
            title="Malicious IPs",
            iocs={"ipv4": ["1.2.3.4", "5.6.7.8"]},
            description="Test detection",
        )
        assert "title: Malicious IPs" in rule
        assert "description: Test detection" in rule
        assert "1.2.3.4" in rule
        assert "5.6.7.8" in rule
        assert "dst_ip" in rule
        assert "src_ip" in rule
        assert "detection:" in rule
        assert "condition:" in rule
        assert "level: high" in rule

    def test_domain_rule(self):
        rule = generate_sigma_rule(
            title="Bad Domains",
            iocs={"domain": ["evil.com", "malware.net"]},
        )
        assert "cs-host" in rule
        assert "evil.com" in rule
        assert "malware.net" in rule

    def test_url_rule(self):
        rule = generate_sigma_rule(
            title="Bad URLs",
            iocs={"url": ["https://evil.com/payload.exe"]},
        )
        assert "cs-uri" in rule
        assert "https://evil.com/payload.exe" in rule

    def test_mixed_iocs(self):
        rule = generate_sigma_rule(
            title="Mixed IOCs",
            iocs={
                "ipv4": ["1.2.3.4"],
                "domain": ["evil.com"],
                "url": ["https://evil.com/bad"],
            },
        )
        assert "dst_ip" in rule
        assert "cs-host" in rule
        assert "cs-uri" in rule
        assert " or " in rule

    def test_empty_iocs(self):
        rule = generate_sigma_rule(title="Empty", iocs={})
        assert "condition: false" in rule

    def test_custom_level_and_status(self):
        rule = generate_sigma_rule(
            title="Custom",
            iocs={"ipv4": ["1.2.3.4"]},
            level="critical",
            status="stable",
        )
        assert "level: critical" in rule
        assert "status: stable" in rule

    def test_custom_logsource(self):
        rule = generate_sigma_rule(
            title="Firewall Rule",
            iocs={"ipv4": ["1.2.3.4"]},
            logsource_category="firewall",
            logsource_product="paloalto",
        )
        assert "category: firewall" in rule
        assert "product: paloalto" in rule

    def test_tags_included(self):
        rule = generate_sigma_rule(
            title="Tagged",
            iocs={"ipv4": ["1.2.3.4"]},
            tags=["attack.command_and_control", "attack.t1071"],
        )
        assert "tags:" in rule
        assert "- attack.command_and_control" in rule
        assert "- attack.t1071" in rule

    def test_deterministic_id(self):
        rule1 = generate_sigma_rule(title="Same Title", iocs={"ipv4": ["1.2.3.4"]})
        rule2 = generate_sigma_rule(title="Same Title", iocs={"ipv4": ["1.2.3.4"]})
        # Extract IDs
        id1 = [l for l in rule1.split("\n") if l.startswith("id:")][0]
        id2 = [l for l in rule2.split("\n") if l.startswith("id:")][0]
        assert id1 == id2

    def test_ip_limit_per_field(self):
        ips = [f"10.0.0.{i}" for i in range(30)]
        rule = generate_sigma_rule(title="Many IPs", iocs={"ipv4": ips})
        # Should limit to 20 per field
        ip_count = rule.count("10.0.0.")
        # dst_ip and src_ip each get up to 20
        assert ip_count <= 40

    def test_false_positives_section(self):
        rule = generate_sigma_rule(title="Test", iocs={"ipv4": ["1.2.3.4"]})
        assert "falsepositives:" in rule


class TestGenerateSigmaDNSRule:
    """Tests for DNS-specific Sigma rule generation."""

    def test_basic_dns_rule(self):
        rule = generate_sigma_dns_rule(
            title="DNS C2 Detection",
            domains=["evil.com", "c2.malware.net"],
            description="Detect DNS queries to C2 domains",
        )
        assert "title: DNS C2 Detection" in rule
        assert "category: dns" in rule
        assert "query|endswith:" in rule
        assert "'.evil.com'" in rule
        assert "'evil.com'" in rule
        assert "'.c2.malware.net'" in rule
        assert "condition: selection" in rule

    def test_dns_rule_level(self):
        rule = generate_sigma_dns_rule(
            title="Test",
            domains=["evil.com"],
            level="critical",
        )
        assert "level: critical" in rule

    def test_dns_rule_tags(self):
        rule = generate_sigma_dns_rule(
            title="Test",
            domains=["evil.com"],
            tags=["attack.t1071.004"],
        )
        assert "- attack.t1071.004" in rule

    def test_dns_domain_limit(self):
        domains = [f"domain{i}.com" for i in range(60)]
        rule = generate_sigma_dns_rule(title="Many Domains", domains=domains)
        # Should limit to 50 domains (each produces 2 lines: endswith and exact)
        # Count unique domain references
        assert "domain50.com" not in rule
        assert "domain49.com" in rule


class TestGenerateSigmaFirewallRule:
    """Tests for firewall-specific Sigma rule generation."""

    def test_both_directions(self):
        rule = generate_sigma_firewall_rule(
            title="Firewall Block",
            ips=["1.2.3.4", "5.6.7.8"],
            direction="both",
        )
        assert "selection_dst:" in rule
        assert "dst_ip:" in rule
        assert "selection_src:" in rule
        assert "src_ip:" in rule
        assert "condition: selection_dst or selection_src" in rule

    def test_outbound_only(self):
        rule = generate_sigma_firewall_rule(
            title="Outbound",
            ips=["1.2.3.4"],
            direction="outbound",
        )
        assert "selection_dst:" in rule
        assert "dst_ip:" in rule
        assert "selection_src:" not in rule
        assert "condition: selection_dst" in rule

    def test_inbound_only(self):
        rule = generate_sigma_firewall_rule(
            title="Inbound",
            ips=["1.2.3.4"],
            direction="inbound",
        )
        assert "selection_src:" in rule
        assert "src_ip:" in rule
        assert "selection_dst:" not in rule
        assert "condition: selection_src" in rule

    def test_firewall_category(self):
        rule = generate_sigma_firewall_rule(
            title="Test",
            ips=["1.2.3.4"],
        )
        assert "category: firewall" in rule

    def test_ip_limit(self):
        ips = [f"10.0.{i // 256}.{i % 256}" for i in range(60)]
        rule = generate_sigma_firewall_rule(title="Many", ips=ips, direction="outbound")
        # Should limit to 50 IPs per direction
        assert "10.0.0.50" not in rule
        assert "10.0.0.49" in rule
