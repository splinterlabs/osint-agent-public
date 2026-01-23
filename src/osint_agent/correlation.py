"""Pattern and TTP correlation engine.

Correlates IOCs across sources, maps behaviors to ATT&CK techniques,
and identifies related indicators.
"""

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class CorrelationResult:
    """Result of correlation analysis."""

    ioc_type: str
    ioc_value: str
    sources: list[str] = field(default_factory=list)
    related_iocs: list[dict] = field(default_factory=list)
    campaigns: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)
    confidence: float = 0.0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: list[str] = field(default_factory=list)


@dataclass
class ClusterResult:
    """Result of IOC clustering."""

    cluster_id: str
    primary_indicator: str
    indicator_type: str
    members: list[dict] = field(default_factory=list)
    common_sources: list[str] = field(default_factory=list)
    time_window: Optional[tuple[str, str]] = None
    confidence: float = 0.0


class CorrelationEngine:
    """Engine for correlating IOCs and mapping behaviors to TTPs."""

    # Infrastructure correlation patterns
    INFRA_PATTERNS = {
        "shared_hosting": r"(?:amazonaws|digitalocean|linode|vultr|cloudflare)",
        "dynamic_dns": r"(?:duckdns|no-ip|dynu|freedns)",
        "bulletproof": r"(?:dataclub|leaseweb|selectel|hetzner)",
    }

    # Behavioral patterns mapped to techniques
    BEHAVIOR_TECHNIQUES = {
        # Initial Access
        r"phish(?:ing)?": ["T1566", "T1566.001", "T1566.002"],
        r"spear\s*phish": ["T1566.001"],
        r"drive.by": ["T1189"],
        r"exploit(?:ed|ing)?\s+public": ["T1190"],
        r"supply\s*chain": ["T1195"],
        # Execution
        r"powershell": ["T1059.001"],
        r"cmd(?:\.exe)?": ["T1059.003"],
        r"wmi(?:c)?": ["T1047"],
        r"mshta": ["T1218.005"],
        r"rundll32": ["T1218.011"],
        r"regsvr32": ["T1218.010"],
        r"msiexec": ["T1218.007"],
        r"script(?:ing)?": ["T1059"],
        # Persistence
        r"scheduled\s*task": ["T1053.005"],
        r"registry\s*run": ["T1547.001"],
        r"startup\s*folder": ["T1547.001"],
        r"service\s*(?:install|create)": ["T1543.003"],
        r"boot(?:kit)?": ["T1542"],
        # Privilege Escalation
        r"uac\s*bypass": ["T1548.002"],
        r"token\s*(?:steal|manipul)": ["T1134"],
        r"exploit(?:ed|ing)?\s+(?:local|priv)": ["T1068"],
        # Defense Evasion
        r"obfuscat": ["T1027"],
        r"pack(?:ed|er)": ["T1027.002"],
        r"process\s*(?:inject|hollow)": ["T1055"],
        r"disable\s*(?:av|antivirus|defender)": ["T1562.001"],
        r"timestomp": ["T1070.006"],
        r"clear\s*(?:log|event)": ["T1070.001"],
        # Credential Access
        r"mimikatz": ["T1003.001"],
        r"credential\s*dump": ["T1003"],
        r"lsass": ["T1003.001"],
        r"kerberoast": ["T1558.003"],
        r"pass(?:word)?\s*spray": ["T1110.003"],
        r"brute\s*force": ["T1110"],
        # Discovery
        r"network\s*scan": ["T1046"],
        r"port\s*scan": ["T1046"],
        r"whoami": ["T1033"],
        r"(?:ad|active\s*directory)\s*enum": ["T1087.002"],
        # Lateral Movement
        r"rdp": ["T1021.001"],
        r"psexec": ["T1021.002", "T1569.002"],
        r"wmi(?:c)?\s*(?:remote|lateral)": ["T1021.003"],
        r"ssh\s*(?:lateral|pivot)": ["T1021.004"],
        r"pass\s*the\s*hash": ["T1550.002"],
        r"pass\s*the\s*ticket": ["T1550.003"],
        # Collection
        r"keylog": ["T1056.001"],
        r"screen\s*capture": ["T1113"],
        r"clipboard": ["T1115"],
        r"email\s*collect": ["T1114"],
        # Command and Control
        r"c2|c&c|command\s*(?:and|&)\s*control": ["T1071"],
        r"beacon(?:ing)?": ["T1071.001"],
        r"dns\s*tunnel": ["T1071.004"],
        r"cobalt\s*strike": ["T1071.001"],
        # Exfiltration
        r"exfiltrat": ["T1041"],
        r"data\s*(?:theft|steal)": ["T1041"],
        # Impact
        r"ransomware": ["T1486"],
        r"encrypt(?:ed|ing)?\s*files": ["T1486"],
        r"wiper": ["T1485"],
        r"defac(?:e|ement)": ["T1491"],
    }

    def __init__(self, campaign_manager=None, attack_client=None):
        """Initialize correlation engine.

        Args:
            campaign_manager: Optional CampaignManager for campaign correlation
            attack_client: Optional ATTACKClient for technique lookups
        """
        self.campaign_manager = campaign_manager
        self.attack_client = attack_client
        self._ioc_index: dict[str, list[dict]] = defaultdict(list)

    def index_ioc(
        self,
        ioc_type: str,
        value: str,
        source: str,
        timestamp: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> None:
        """Add IOC to correlation index.

        Args:
            ioc_type: Type of IOC
            value: IOC value
            source: Source of the IOC
            timestamp: When IOC was observed
            metadata: Additional metadata
        """
        key = f"{ioc_type}:{value}"
        self._ioc_index[key].append(
            {
                "type": ioc_type,
                "value": value,
                "source": source,
                "timestamp": timestamp or datetime.utcnow().isoformat(),
                "metadata": metadata or {},
            }
        )

    def correlate_ioc(self, ioc_type: str, value: str) -> CorrelationResult:
        """Correlate an IOC across all indexed data.

        Args:
            ioc_type: Type of IOC
            value: IOC value

        Returns:
            Correlation result with related data
        """
        result = CorrelationResult(ioc_type=ioc_type, ioc_value=value)
        key = f"{ioc_type}:{value}"

        # Get all sightings of this IOC
        sightings = self._ioc_index.get(key, [])
        result.sources = list(set(s["source"] for s in sightings))

        if sightings:
            timestamps = [s["timestamp"] for s in sightings if s.get("timestamp")]
            if timestamps:
                result.first_seen = min(timestamps)
                result.last_seen = max(timestamps)

        # Find related IOCs (same source, close in time)
        result.related_iocs = self._find_related_iocs(ioc_type, value, sightings)

        # Check campaigns
        if self.campaign_manager:
            campaigns = self.campaign_manager.find_by_ioc(ioc_type, value)
            result.campaigns = [c.name for c in campaigns]
            for campaign in campaigns:
                if campaign.threat_actor:
                    result.threat_actors.append(campaign.threat_actor)
                result.techniques.extend([t.technique_id for t in campaign.ttps])

        # Calculate confidence based on number of sources and sightings
        result.confidence = self._calculate_confidence(sightings, result)

        return result

    def _find_related_iocs(
        self, ioc_type: str, value: str, sightings: list[dict]
    ) -> list[dict]:
        """Find IOCs that appear alongside the given IOC."""
        related = []
        sources = set(s["source"] for s in sightings)

        for key, entries in self._ioc_index.items():
            if key == f"{ioc_type}:{value}":
                continue

            # Check if any entry shares a source
            for entry in entries:
                if entry["source"] in sources:
                    entry_type, entry_value = key.split(":", 1)
                    related.append(
                        {
                            "type": entry_type,
                            "value": entry_value,
                            "shared_sources": [entry["source"]],
                        }
                    )
                    break

        return related[:20]  # Limit results

    def _calculate_confidence(
        self, sightings: list[dict], result: CorrelationResult
    ) -> float:
        """Calculate confidence score for correlation."""
        score = 0.0

        # Number of sources (max 0.4)
        score += min(len(result.sources) * 0.1, 0.4)

        # Number of sightings (max 0.2)
        score += min(len(sightings) * 0.05, 0.2)

        # Campaign association (0.2)
        if result.campaigns:
            score += 0.2

        # Related IOCs (max 0.2)
        score += min(len(result.related_iocs) * 0.02, 0.2)

        return min(score, 1.0)

    def map_behavior_to_techniques(self, text: str) -> list[dict]:
        """Map behavioral description to ATT&CK techniques.

        Args:
            text: Behavioral description

        Returns:
            List of matching techniques with confidence
        """
        text_lower = text.lower()
        technique_matches: dict[str, float] = defaultdict(float)

        for pattern, techniques in self.BEHAVIOR_TECHNIQUES.items():
            if re.search(pattern, text_lower):
                for technique in techniques:
                    technique_matches[technique] += 1.0

        # Sort by match strength
        results = []
        for technique_id, score in sorted(
            technique_matches.items(), key=lambda x: x[1], reverse=True
        ):
            technique_info = {"id": technique_id, "confidence": min(score / 3.0, 1.0)}

            # Get full technique info if client available
            if self.attack_client:
                full_info = self.attack_client.get_technique(technique_id)
                if full_info:
                    technique_info["name"] = full_info["name"]
                    technique_info["tactics"] = full_info["tactics"]

            results.append(technique_info)

        return results[:10]

    def cluster_iocs(
        self,
        iocs: list[dict],
        time_window_minutes: int = 60,
        min_cluster_size: int = 2,
    ) -> list[ClusterResult]:
        """Cluster related IOCs based on shared attributes and timing.

        Args:
            iocs: List of IOCs with type, value, source, timestamp
            time_window_minutes: Time window for clustering
            min_cluster_size: Minimum IOCs per cluster

        Returns:
            List of IOC clusters
        """
        from datetime import timedelta

        clusters: list[ClusterResult] = []
        processed = set()

        # Group by source first
        by_source: dict[str, list[dict]] = defaultdict(list)
        for ioc in iocs:
            by_source[ioc.get("source", "unknown")].append(ioc)

        # Find clusters within each source
        for source, source_iocs in by_source.items():
            # Sort by timestamp
            sorted_iocs = sorted(
                source_iocs,
                key=lambda x: x.get("timestamp", ""),
            )

            current_cluster: list[dict] = []
            cluster_start: Optional[datetime] = None

            for ioc in sorted_iocs:
                ioc_key = f"{ioc['type']}:{ioc['value']}"
                if ioc_key in processed:
                    continue

                try:
                    ioc_time = datetime.fromisoformat(
                        ioc.get("timestamp", "").replace("Z", "+00:00")
                    )
                except (ValueError, AttributeError):
                    ioc_time = None

                if not current_cluster:
                    current_cluster.append(ioc)
                    cluster_start = ioc_time
                    processed.add(ioc_key)
                elif ioc_time and cluster_start:
                    if ioc_time - cluster_start <= timedelta(minutes=time_window_minutes):
                        current_cluster.append(ioc)
                        processed.add(ioc_key)
                    else:
                        # Save current cluster and start new one
                        if len(current_cluster) >= min_cluster_size:
                            clusters.append(self._create_cluster(current_cluster, source))
                        current_cluster = [ioc]
                        cluster_start = ioc_time
                        processed.add(ioc_key)

            # Don't forget last cluster
            if len(current_cluster) >= min_cluster_size:
                clusters.append(self._create_cluster(current_cluster, source))

        return clusters

    def _create_cluster(self, iocs: list[dict], source: str) -> ClusterResult:
        """Create cluster from IOC list."""
        import uuid

        # Find most common type as primary
        type_counts: dict[str, int] = defaultdict(int)
        for ioc in iocs:
            type_counts[ioc["type"]] += 1

        primary_type = max(type_counts.items(), key=lambda x: x[1])[0]
        primary_ioc = next(i for i in iocs if i["type"] == primary_type)

        timestamps = [i.get("timestamp") for i in iocs if i.get("timestamp")]
        time_window = (min(timestamps), max(timestamps)) if timestamps else None

        return ClusterResult(
            cluster_id=str(uuid.uuid4())[:8],
            primary_indicator=primary_ioc["value"],
            indicator_type=primary_type,
            members=iocs,
            common_sources=[source],
            time_window=time_window,
            confidence=min(len(iocs) * 0.15, 1.0),
        )

    def find_infrastructure_patterns(self, domains: list[str]) -> dict[str, list[str]]:
        """Identify infrastructure patterns in domains.

        Args:
            domains: List of domain names

        Returns:
            Dictionary of pattern type to matching domains
        """
        results: dict[str, list[str]] = defaultdict(list)

        for domain in domains:
            domain_lower = domain.lower()
            for pattern_name, pattern in self.INFRA_PATTERNS.items():
                if re.search(pattern, domain_lower):
                    results[pattern_name].append(domain)

        return dict(results)

    def correlate_campaign_iocs(
        self, campaign_id: str
    ) -> dict[str, Any]:
        """Perform deep correlation analysis on campaign IOCs.

        Args:
            campaign_id: Campaign ID

        Returns:
            Correlation analysis results
        """
        if not self.campaign_manager:
            return {"error": "Campaign manager not available"}

        campaign = self.campaign_manager.get(campaign_id)
        if not campaign:
            return {"error": f"Campaign {campaign_id} not found"}

        results = {
            "campaign_id": campaign_id,
            "campaign_name": campaign.name,
            "total_iocs": len(campaign.iocs),
            "ioc_types": defaultdict(int),
            "infrastructure_patterns": {},
            "related_campaigns": [],
            "technique_coverage": [],
        }

        # Analyze IOC types
        domains = []
        for ioc in campaign.iocs:
            results["ioc_types"][ioc.ioc_type] += 1
            if ioc.ioc_type == "domain":
                domains.append(ioc.value)

        # Find infrastructure patterns
        if domains:
            results["infrastructure_patterns"] = self.find_infrastructure_patterns(domains)

        # Find related campaigns by shared IOCs
        related_campaign_ids = set()
        for ioc in campaign.iocs[:50]:  # Limit for performance
            related = self.campaign_manager.find_by_ioc(ioc.ioc_type, ioc.value)
            for rel in related:
                if rel.id != campaign_id:
                    related_campaign_ids.add(rel.id)

        results["related_campaigns"] = list(related_campaign_ids)

        # Analyze technique coverage by tactic
        tactic_coverage: dict[str, list[str]] = defaultdict(list)
        for ttp in campaign.ttps:
            tactic_coverage[ttp.tactic].append(ttp.technique_id)
        results["technique_coverage"] = dict(tactic_coverage)

        return results
