"""Pattern and TTP correlation engine.

Correlates IOCs across sources, maps behaviors to ATT&CK techniques,
and identifies related indicators.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from osint_agent.parallel import get_workers, parallel_collect_sets

logger = logging.getLogger(__name__)


def _load_behavior_techniques() -> dict[str, list[str]]:
    """Load behavior-to-technique mappings from config file.

    Falls back to empty dict if config file not found.
    """
    config_paths = [
        Path(__file__).parent.parent.parent / "config" / "behavior_techniques.json",
        Path("config/behavior_techniques.json"),
    ]

    for config_path in config_paths:
        if config_path.exists():
            try:
                with open(config_path) as f:
                    data = json.load(f)
                    return data.get("patterns", {})
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load behavior techniques config: {e}")

    logger.warning("Behavior techniques config not found, using empty mappings")
    return {}


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

    # Confidence scoring weights
    SOURCE_WEIGHT = 0.1
    SOURCE_MAX = 0.4
    SIGHTING_WEIGHT = 0.05
    SIGHTING_MAX = 0.2
    CAMPAIGN_BONUS = 0.2
    RELATED_IOC_WEIGHT = 0.02
    RELATED_IOC_MAX = 0.2
    BEHAVIOR_MATCH_DIVISOR = 3.0
    CLUSTER_CONFIDENCE_WEIGHT = 0.15
    MAX_RELATED_IOCS = 20
    MAX_TECHNIQUE_RESULTS = 10

    # Infrastructure correlation patterns
    INFRA_PATTERNS = {
        "shared_hosting": r"(?:amazonaws|digitalocean|linode|vultr|cloudflare)",
        "dynamic_dns": r"(?:duckdns|no-ip|dynu|freedns)",
        "bulletproof": r"(?:dataclub|leaseweb|selectel|hetzner)",
    }

    # Behavioral patterns mapped to techniques - loaded from config
    _behavior_techniques: Optional[dict[str, list[str]]] = None

    @classmethod
    def get_behavior_techniques(cls) -> dict[str, list[str]]:
        """Get behavior-to-technique mappings (lazy loaded from config)."""
        if cls._behavior_techniques is None:
            cls._behavior_techniques = _load_behavior_techniques()
        return cls._behavior_techniques

    @classmethod
    def reload_behavior_techniques(cls) -> None:
        """Force reload of behavior techniques from config."""
        cls._behavior_techniques = _load_behavior_techniques()

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
                "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
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

        return related[:self.MAX_RELATED_IOCS]

    def _calculate_confidence(
        self, sightings: list[dict], result: CorrelationResult
    ) -> float:
        """Calculate confidence score for correlation."""
        score = 0.0

        # Number of sources
        score += min(len(result.sources) * self.SOURCE_WEIGHT, self.SOURCE_MAX)

        # Number of sightings
        score += min(len(sightings) * self.SIGHTING_WEIGHT, self.SIGHTING_MAX)

        # Campaign association
        if result.campaigns:
            score += self.CAMPAIGN_BONUS

        # Related IOCs
        score += min(len(result.related_iocs) * self.RELATED_IOC_WEIGHT, self.RELATED_IOC_MAX)

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

        for pattern, techniques in self.get_behavior_techniques().items():
            if re.search(pattern, text_lower):
                for technique in techniques:
                    technique_matches[technique] += 1.0

        # Sort by match strength
        results = []
        for technique_id, score in sorted(
            technique_matches.items(), key=lambda x: x[1], reverse=True
        ):
            technique_info = {"id": technique_id, "confidence": min(score / self.BEHAVIOR_MATCH_DIVISOR, 1.0)}

            # Get full technique info if client available
            if self.attack_client:
                full_info = self.attack_client.get_technique(technique_id)
                if full_info:
                    technique_info["name"] = full_info["name"]
                    technique_info["tactics"] = full_info["tactics"]

            results.append(technique_info)

        return results[:self.MAX_TECHNIQUE_RESULTS]

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
            confidence=min(len(iocs) * self.CLUSTER_CONFIDENCE_WEIGHT, 1.0),
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

        # Find related campaigns by shared IOCs (parallelized)
        def _find_related(ioc: Any) -> set[str] | None:
            related = self.campaign_manager.find_by_ioc(ioc.ioc_type, ioc.value)
            ids = {rel.id for rel in related if rel.id != campaign_id}
            return ids if ids else None

        workers = get_workers("campaign_correlation_workers", 20)
        related_campaign_ids = parallel_collect_sets(
            _find_related,
            campaign.iocs[:50],
            max_workers=workers,
            label="campaign_correlation",
        )

        results["related_campaigns"] = list(related_campaign_ids)

        # Analyze technique coverage by tactic
        tactic_coverage: dict[str, list[str]] = defaultdict(list)
        for ttp in campaign.ttps:
            tactic_coverage[ttp.tactic].append(ttp.technique_id)
        results["technique_coverage"] = dict(tactic_coverage)

        return results
