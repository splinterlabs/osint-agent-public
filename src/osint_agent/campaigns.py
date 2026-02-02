"""Campaign tracking and management system.

Provides infrastructure for tracking threat campaigns, linking IOCs,
and managing investigation lifecycle.
"""

from __future__ import annotations

import json
import logging
import tempfile
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from filelock import FileLock

logger = logging.getLogger(__name__)


class CampaignStatus(str, Enum):
    """Campaign lifecycle status."""

    ACTIVE = "active"
    MONITORING = "monitoring"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    ARCHIVED = "archived"


class ConfidenceLevel(str, Enum):
    """Confidence level for attributions and links."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


@dataclass
class CampaignIOC:
    """IOC linked to a campaign."""

    ioc_type: str  # ipv4, domain, sha256, etc.
    value: str
    first_seen: str
    last_seen: str
    source: str
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    tags: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "source": self.source,
            "confidence": self.confidence.value,
            "tags": self.tags,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CampaignIOC":
        """Create from dictionary."""
        return cls(
            ioc_type=data["ioc_type"],
            value=data["value"],
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
            source=data["source"],
            confidence=ConfidenceLevel(data.get("confidence", "medium")),
            tags=data.get("tags", []),
            notes=data.get("notes", ""),
        )


@dataclass
class CampaignTTP:
    """TTP (Tactic, Technique, Procedure) linked to a campaign."""

    technique_id: str  # ATT&CK ID like T1059.001
    technique_name: str
    tactic: str
    observed_at: str
    evidence: str
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "observed_at": self.observed_at,
            "evidence": self.evidence,
            "confidence": self.confidence.value,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CampaignTTP":
        """Create from dictionary."""
        return cls(
            technique_id=data["technique_id"],
            technique_name=data["technique_name"],
            tactic=data["tactic"],
            observed_at=data["observed_at"],
            evidence=data["evidence"],
            confidence=ConfidenceLevel(data.get("confidence", "medium")),
        )


@dataclass
class Campaign:
    """Threat campaign entity."""

    id: str
    name: str
    description: str
    status: CampaignStatus
    created_at: str
    updated_at: str
    threat_actor: Optional[str] = None
    threat_actor_aliases: list[str] = field(default_factory=list)
    targeted_sectors: list[str] = field(default_factory=list)
    targeted_regions: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    iocs: list[CampaignIOC] = field(default_factory=list)
    ttps: list[CampaignTTP] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "threat_actor": self.threat_actor,
            "threat_actor_aliases": self.threat_actor_aliases,
            "targeted_sectors": self.targeted_sectors,
            "targeted_regions": self.targeted_regions,
            "malware_families": self.malware_families,
            "cves": self.cves,
            "iocs": [ioc.to_dict() for ioc in self.iocs],
            "ttps": [ttp.to_dict() for ttp in self.ttps],
            "references": self.references,
            "tags": self.tags,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Campaign":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            status=CampaignStatus(data["status"]),
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            threat_actor=data.get("threat_actor"),
            threat_actor_aliases=data.get("threat_actor_aliases", []),
            targeted_sectors=data.get("targeted_sectors", []),
            targeted_regions=data.get("targeted_regions", []),
            malware_families=data.get("malware_families", []),
            cves=data.get("cves", []),
            iocs=[CampaignIOC.from_dict(ioc) for ioc in data.get("iocs", [])],
            ttps=[CampaignTTP.from_dict(ttp) for ttp in data.get("ttps", [])],
            references=data.get("references", []),
            tags=data.get("tags", []),
            notes=data.get("notes", ""),
        )

    def add_ioc(
        self,
        ioc_type: str,
        value: str,
        source: str,
        confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM,
        tags: Optional[list[str]] = None,
        notes: str = "",
    ) -> CampaignIOC:
        """Add IOC to campaign."""
        now = datetime.now(timezone.utc).isoformat()

        # Check if IOC already exists
        for existing in self.iocs:
            if existing.ioc_type == ioc_type and existing.value == value:
                existing.last_seen = now
                existing.source = source  # Update source
                if tags:
                    existing.tags = list(set(existing.tags + tags))
                return existing

        ioc = CampaignIOC(
            ioc_type=ioc_type,
            value=value,
            first_seen=now,
            last_seen=now,
            source=source,
            confidence=confidence,
            tags=tags or [],
            notes=notes,
        )
        self.iocs.append(ioc)
        self.updated_at = now
        return ioc

    def add_ttp(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        evidence: str,
        confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM,
    ) -> CampaignTTP:
        """Add TTP to campaign."""
        now = datetime.now(timezone.utc).isoformat()

        # Check if TTP already exists
        for existing in self.ttps:
            if existing.technique_id == technique_id:
                existing.observed_at = now
                existing.evidence = evidence
                return existing

        ttp = CampaignTTP(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            observed_at=now,
            evidence=evidence,
            confidence=confidence,
        )
        self.ttps.append(ttp)
        self.updated_at = now
        return ttp

    def add_cve(self, cve_id: str) -> None:
        """Add CVE to campaign."""
        if cve_id not in self.cves:
            self.cves.append(cve_id)
            self.updated_at = datetime.now(timezone.utc).isoformat()

    def update_status(self, status: CampaignStatus) -> None:
        """Update campaign status."""
        self.status = status
        self.updated_at = datetime.now(timezone.utc).isoformat()


class CampaignManager:
    """Manages campaign storage and retrieval.

    Uses index data structures for O(1) lookups by IOC, TTP, and CVE.
    """

    # Lock timeout in seconds
    LOCK_TIMEOUT = 10

    def __init__(self, data_dir: Optional[Path] = None):
        """Initialize campaign manager.

        Args:
            data_dir: Directory for campaign data storage
        """
        self.data_dir = data_dir or Path("data/campaigns")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._campaigns: dict[str, Campaign] = {}
        # Index structures for fast lookups
        self._ioc_index: dict[str, set[str]] = {}  # "type:value" -> campaign_ids
        self._ttp_index: dict[str, set[str]] = {}  # technique_id -> campaign_ids
        self._cve_index: dict[str, set[str]] = {}  # cve_id -> campaign_ids
        self._lock = FileLock(self._get_lock_path(), timeout=self.LOCK_TIMEOUT)
        self._load_campaigns()

    def _get_storage_path(self) -> Path:
        """Get path to campaigns storage file."""
        return self.data_dir / "campaigns.json"

    def _get_lock_path(self) -> Path:
        """Get path to lock file."""
        return self.data_dir / "campaigns.json.lock"

    def _load_campaigns(self) -> None:
        """Load campaigns from storage with file locking."""
        storage_path = self._get_storage_path()
        if not storage_path.exists():
            return

        try:
            with self._lock:
                with open(storage_path) as f:
                    data = json.load(f)
                    for campaign_data in data.get("campaigns", []):
                        campaign = Campaign.from_dict(campaign_data)
                        self._campaigns[campaign.id] = campaign
                        self._index_campaign(campaign)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load campaigns: {e}")

    def _index_campaign(self, campaign: Campaign) -> None:
        """Add campaign to all indexes."""
        # Index IOCs
        for ioc in campaign.iocs:
            key = f"{ioc.ioc_type}:{ioc.value}"
            if key not in self._ioc_index:
                self._ioc_index[key] = set()
            self._ioc_index[key].add(campaign.id)

        # Index TTPs
        for ttp in campaign.ttps:
            if ttp.technique_id not in self._ttp_index:
                self._ttp_index[ttp.technique_id] = set()
            self._ttp_index[ttp.technique_id].add(campaign.id)

        # Index CVEs
        for cve_id in campaign.cves:
            if cve_id not in self._cve_index:
                self._cve_index[cve_id] = set()
            self._cve_index[cve_id].add(campaign.id)

    def _unindex_campaign(self, campaign: Campaign) -> None:
        """Remove campaign from all indexes."""
        # Unindex IOCs
        for ioc in campaign.iocs:
            key = f"{ioc.ioc_type}:{ioc.value}"
            if key in self._ioc_index:
                self._ioc_index[key].discard(campaign.id)
                if not self._ioc_index[key]:
                    del self._ioc_index[key]

        # Unindex TTPs
        for ttp in campaign.ttps:
            if ttp.technique_id in self._ttp_index:
                self._ttp_index[ttp.technique_id].discard(campaign.id)
                if not self._ttp_index[ttp.technique_id]:
                    del self._ttp_index[ttp.technique_id]

        # Unindex CVEs
        for cve_id in campaign.cves:
            if cve_id in self._cve_index:
                self._cve_index[cve_id].discard(campaign.id)
                if not self._cve_index[cve_id]:
                    del self._cve_index[cve_id]

    def _reindex_campaign(self, campaign: Campaign) -> None:
        """Reindex a campaign after updates."""
        # Get old version if exists
        old_campaign = self._campaigns.get(campaign.id)
        if old_campaign:
            self._unindex_campaign(old_campaign)
        self._index_campaign(campaign)

    def _save_campaigns(self) -> None:
        """Save campaigns to storage with atomic write, file locking, and secure permissions.

        Uses write-to-temp-then-rename pattern for atomicity.
        SECURITY: Sets restrictive file permissions (0600) to prevent unauthorized access.
        Campaign files contain sensitive IOCs, TTPs, and threat intelligence.
        """
        import os

        storage_path = self._get_storage_path()
        try:
            with self._lock:
                # Write to temporary file first with secure permissions
                old_umask = os.umask(0o077)  # Ensure temp file is created with 600
                try:
                    fd, tmp_path = tempfile.mkstemp(
                        dir=self.data_dir,
                        prefix=".campaigns_",
                        suffix=".json.tmp",
                    )
                finally:
                    os.umask(old_umask)  # Restore original umask

                try:
                    with open(fd, "w") as f:
                        json.dump(
                            {"campaigns": [c.to_dict() for c in self._campaigns.values()]},
                            f,
                            indent=2,
                        )

                    # Explicitly set restrictive permissions (owner read/write only)
                    os.chmod(tmp_path, 0o600)

                    # Atomic rename (works on POSIX, best-effort on Windows)
                    Path(tmp_path).replace(storage_path)

                    # Verify final file permissions (defense in depth)
                    os.chmod(storage_path, 0o600)
                except Exception:
                    # Clean up temp file on failure
                    Path(tmp_path).unlink(missing_ok=True)
                    raise
        except IOError as e:
            logger.error(f"Failed to save campaigns: {e}")

    def create(
        self,
        name: str,
        description: str,
        threat_actor: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> Campaign:
        """Create a new campaign.

        Args:
            name: Campaign name
            description: Campaign description
            threat_actor: Attributed threat actor
            tags: Campaign tags

        Returns:
            Created campaign
        """
        now = datetime.now(timezone.utc).isoformat()
        campaign = Campaign(
            id=str(uuid.uuid4())[:8],
            name=name,
            description=description,
            status=CampaignStatus.ACTIVE,
            created_at=now,
            updated_at=now,
            threat_actor=threat_actor,
            tags=tags or [],
        )
        self._campaigns[campaign.id] = campaign
        self._index_campaign(campaign)
        self._save_campaigns()
        return campaign

    def get(self, campaign_id: str) -> Optional[Campaign]:
        """Get campaign by ID."""
        return self._campaigns.get(campaign_id)

    def get_by_name(self, name: str) -> Optional[Campaign]:
        """Get campaign by name (case-insensitive)."""
        name_lower = name.lower()
        for campaign in self._campaigns.values():
            if campaign.name.lower() == name_lower:
                return campaign
        return None

    def list(
        self,
        status: Optional[CampaignStatus] = None,
        threat_actor: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> list[Campaign]:
        """List campaigns with optional filters.

        Args:
            status: Filter by status
            threat_actor: Filter by threat actor
            tag: Filter by tag

        Returns:
            List of matching campaigns
        """
        results = []
        for campaign in self._campaigns.values():
            if status and campaign.status != status:
                continue
            if threat_actor and campaign.threat_actor != threat_actor:
                continue
            if tag and tag not in campaign.tags:
                continue
            results.append(campaign)

        # Sort by updated_at descending
        results.sort(key=lambda c: c.updated_at, reverse=True)
        return results

    def update(self, campaign: Campaign) -> None:
        """Update campaign in storage."""
        campaign.updated_at = datetime.now(timezone.utc).isoformat()
        self._reindex_campaign(campaign)
        self._campaigns[campaign.id] = campaign
        self._save_campaigns()

    def delete(self, campaign_id: str) -> bool:
        """Delete campaign by ID."""
        if campaign_id in self._campaigns:
            campaign = self._campaigns[campaign_id]
            self._unindex_campaign(campaign)
            del self._campaigns[campaign_id]
            self._save_campaigns()
            return True
        return False

    def find_by_ioc(self, ioc_type: str, value: str) -> list[Campaign]:
        """Find campaigns containing an IOC.

        Uses index for O(1) lookup instead of scanning all campaigns.

        Args:
            ioc_type: Type of IOC
            value: IOC value

        Returns:
            List of campaigns containing the IOC
        """
        key = f"{ioc_type}:{value}"
        campaign_ids = self._ioc_index.get(key, set())
        return [self._campaigns[cid] for cid in campaign_ids if cid in self._campaigns]

    def find_by_ttp(self, technique_id: str) -> list[Campaign]:
        """Find campaigns using a technique.

        Uses index for O(1) lookup instead of scanning all campaigns.

        Args:
            technique_id: ATT&CK technique ID

        Returns:
            List of campaigns using the technique
        """
        campaign_ids = self._ttp_index.get(technique_id, set())
        return [self._campaigns[cid] for cid in campaign_ids if cid in self._campaigns]

    def find_by_cve(self, cve_id: str) -> list[Campaign]:
        """Find campaigns exploiting a CVE.

        Uses index for O(1) lookup instead of scanning all campaigns.

        Args:
            cve_id: CVE identifier

        Returns:
            List of campaigns exploiting the CVE
        """
        campaign_ids = self._cve_index.get(cve_id, set())
        return [self._campaigns[cid] for cid in campaign_ids if cid in self._campaigns]

    def get_statistics(self) -> dict[str, Any]:
        """Get campaign statistics."""
        total = len(self._campaigns)
        by_status = {}
        total_iocs = 0
        total_ttps = 0

        for campaign in self._campaigns.values():
            status = campaign.status.value
            by_status[status] = by_status.get(status, 0) + 1
            total_iocs += len(campaign.iocs)
            total_ttps += len(campaign.ttps)

        return {
            "total_campaigns": total,
            "by_status": by_status,
            "total_iocs": total_iocs,
            "total_ttps": total_ttps,
        }
