"""MITRE ATT&CK framework client.

Fetches techniques, tactics, mitigations, and groups from the ATT&CK STIX data.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .base import BaseClient, ProxyConfig

logger = logging.getLogger(__name__)

# ATT&CK STIX repository URLs
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)


class ATTACKClient(BaseClient):
    """Client for MITRE ATT&CK framework data.

    Fetches and caches ATT&CK STIX data for technique lookups,
    tactic mapping, and threat group information.
    """

    BASE_URL = "https://raw.githubusercontent.com/mitre/cti/master"
    CACHE_TTL_HOURS = 24  # Cache ATT&CK data for 24 hours

    def __init__(
        self,
        cache_dir: Path | None = None,
        timeout: int | None = None,
        proxy: ProxyConfig | None = None,
    ):
        """Initialize ATT&CK client.

        Args:
            cache_dir: Directory for caching ATT&CK data
            timeout: Request timeout
            proxy: Proxy configuration
        """
        super().__init__(timeout=timeout or 60, proxy=proxy)
        self.cache_dir = cache_dir or Path("data/cache/attack")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._data: dict[str, Any] | None = None
        self._techniques: dict[str, dict[str, Any]] = {}
        self._tactics: dict[str, dict[str, Any]] = {}
        self._groups: dict[str, dict[str, Any]] = {}
        self._mitigations: dict[str, dict[str, Any]] = {}
        self._software: dict[str, dict[str, Any]] = {}

    def _get_cache_path(self) -> Path:
        """Get path to cached ATT&CK data."""
        return self.cache_dir / "enterprise-attack.json"

    def _is_cache_valid(self) -> bool:
        """Check if cache is still valid."""
        cache_path = self._get_cache_path()
        if not cache_path.exists():
            return False
        mtime = datetime.fromtimestamp(cache_path.stat().st_mtime)
        return datetime.now() - mtime < timedelta(hours=self.CACHE_TTL_HOURS)

    def _load_data(self) -> dict[str, Any]:
        """Load ATT&CK data from cache or fetch from source."""
        if self._data:
            return self._data

        cache_path = self._get_cache_path()

        # Try loading from cache
        if self._is_cache_valid():
            try:
                with open(cache_path) as f:
                    data: dict[str, Any] = json.load(f)
                    self._data = data
                    self._index_data()
                    return data
            except (OSError, json.JSONDecodeError) as e:
                logger.warning(f"Cache read failed: {e}")

        # Fetch fresh data
        logger.info("Fetching ATT&CK data from MITRE...")
        response = self.session.get(
            f"{self.BASE_URL}/enterprise-attack/enterprise-attack.json",
            timeout=self.timeout,
            proxies=self.proxy.get_proxies() if self.proxy else {},
        )
        response.raise_for_status()
        self._data = response.json()

        # Cache the data
        try:
            with open(cache_path, "w") as f:
                json.dump(self._data, f)
        except OSError as e:
            logger.warning(f"Cache write failed: {e}")

        self._index_data()
        # At this point _data is guaranteed to be set
        assert self._data is not None
        return self._data

    def _index_data(self) -> None:
        """Index ATT&CK objects for fast lookups."""
        if not self._data:
            return

        for obj in self._data.get("objects", []):
            obj_type = obj.get("type")
            external_refs = obj.get("external_references", [])

            # Find ATT&CK ID
            attack_id = None
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    attack_id = ref.get("external_id")
                    break

            if not attack_id:
                continue

            if obj_type == "attack-pattern":
                self._techniques[attack_id] = obj
                # Also index by name for fuzzy matching
                name = obj.get("name", "").lower()
                self._techniques[name] = obj

            elif obj_type == "x-mitre-tactic":
                self._tactics[attack_id] = obj
                shortname = obj.get("x_mitre_shortname", "")
                if shortname:
                    self._tactics[shortname] = obj

            elif obj_type == "intrusion-set":
                self._groups[attack_id] = obj
                name = obj.get("name", "").lower()
                self._groups[name] = obj
                # Index aliases
                for alias in obj.get("aliases", []):
                    self._groups[alias.lower()] = obj

            elif obj_type == "course-of-action":
                self._mitigations[attack_id] = obj

            elif obj_type == "malware" or obj_type == "tool":
                self._software[attack_id] = obj
                name = obj.get("name", "").lower()
                self._software[name] = obj

    def get_technique(self, technique_id: str) -> dict[str, Any] | None:
        """Get technique by ATT&CK ID or name.

        Args:
            technique_id: ATT&CK ID (e.g., T1059) or technique name

        Returns:
            Technique details or None if not found
        """
        self._load_data()
        technique = self._techniques.get(technique_id) or self._techniques.get(technique_id.lower())

        if not technique:
            return None

        # Get ATT&CK ID from external references
        attack_id = None
        url = None
        for ref in technique.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                url = ref.get("url")
                break

        # Get tactics (kill chain phases)
        tactics = []
        for phase in technique.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name"))

        # Get platforms
        platforms = technique.get("x_mitre_platforms", [])

        # Get detection info
        detection = technique.get("x_mitre_detection", "")

        return {
            "id": attack_id,
            "name": technique.get("name", ""),
            "description": technique.get("description", ""),
            "tactics": tactics,
            "platforms": platforms,
            "detection": detection,
            "url": url,
            "is_subtechnique": technique.get("x_mitre_is_subtechnique", False),
            "deprecated": technique.get("x_mitre_deprecated", False),
            "data_sources": technique.get("x_mitre_data_sources", []),
            "permissions_required": technique.get("x_mitre_permissions_required", []),
        }

    def get_tactic(self, tactic_id: str) -> dict[str, Any] | None:
        """Get tactic by ATT&CK ID or shortname.

        Args:
            tactic_id: ATT&CK ID (e.g., TA0001) or shortname (e.g., initial-access)

        Returns:
            Tactic details or None if not found
        """
        self._load_data()
        tactic = self._tactics.get(tactic_id) or self._tactics.get(tactic_id.lower())

        if not tactic:
            return None

        attack_id = None
        url = None
        for ref in tactic.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                url = ref.get("url")
                break

        return {
            "id": attack_id,
            "name": tactic.get("name", ""),
            "shortname": tactic.get("x_mitre_shortname", ""),
            "description": tactic.get("description", ""),
            "url": url,
        }

    def get_group(self, group_id: str) -> dict[str, Any] | None:
        """Get threat group by ATT&CK ID, name, or alias.

        Args:
            group_id: ATT&CK ID (e.g., G0016) or group name/alias

        Returns:
            Group details or None if not found
        """
        self._load_data()
        group = self._groups.get(group_id) or self._groups.get(group_id.lower())

        if not group:
            return None

        attack_id = None
        url = None
        for ref in group.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                url = ref.get("url")
                break

        return {
            "id": attack_id,
            "name": group.get("name", ""),
            "aliases": group.get("aliases", []),
            "description": group.get("description", ""),
            "url": url,
        }

    def get_software(self, software_id: str) -> dict[str, Any] | None:
        """Get malware or tool by ATT&CK ID or name.

        Args:
            software_id: ATT&CK ID (e.g., S0154) or software name

        Returns:
            Software details or None if not found
        """
        self._load_data()
        software = self._software.get(software_id) or self._software.get(software_id.lower())

        if not software:
            return None

        attack_id = None
        url = None
        for ref in software.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id")
                url = ref.get("url")
                break

        return {
            "id": attack_id,
            "name": software.get("name", ""),
            "type": software.get("type", ""),
            "description": software.get("description", ""),
            "platforms": software.get("x_mitre_platforms", []),
            "aliases": software.get("x_mitre_aliases", []),
            "url": url,
        }

    def search_techniques(
        self,
        query: str,
        tactic: str | None = None,
        platform: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Search techniques by keyword.

        Args:
            query: Search query (matches name and description)
            tactic: Filter by tactic shortname
            platform: Filter by platform
            limit: Maximum results

        Returns:
            List of matching techniques
        """
        self._load_data()
        query_lower = query.lower()
        results = []

        # _load_data() ensures _data is not None
        if not self._data:
            return []

        for obj in self._data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated", False):
                continue

            # Check query match
            name = obj.get("name", "").lower()
            desc = obj.get("description", "").lower()
            if query_lower not in name and query_lower not in desc:
                continue

            # Check tactic filter
            if tactic:
                tactics = [
                    p.get("phase_name")
                    for p in obj.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack"
                ]
                if tactic.lower() not in [t.lower() for t in tactics]:
                    continue

            # Check platform filter
            if platform:
                platforms = obj.get("x_mitre_platforms", [])
                if platform.lower() not in [p.lower() for p in platforms]:
                    continue

            # Get ATT&CK ID
            attack_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    attack_id = ref.get("external_id")
                    break

            if attack_id:
                results.append(
                    {
                        "id": attack_id,
                        "name": obj.get("name", ""),
                        "tactics": [
                            p.get("phase_name")
                            for p in obj.get("kill_chain_phases", [])
                            if p.get("kill_chain_name") == "mitre-attack"
                        ],
                    }
                )

            if len(results) >= limit:
                break

        return results

    def list_tactics(self) -> list[dict[str, Any]]:
        """Get all tactics in kill chain order.

        Returns:
            List of tactics
        """
        self._load_data()

        # Define kill chain order
        tactic_order = [
            "reconnaissance",
            "resource-development",
            "initial-access",
            "execution",
            "persistence",
            "privilege-escalation",
            "defense-evasion",
            "credential-access",
            "discovery",
            "lateral-movement",
            "collection",
            "command-and-control",
            "exfiltration",
            "impact",
        ]

        results = []
        for shortname in tactic_order:
            tactic = self._tactics.get(shortname)
            if tactic:
                attack_id = None
                for ref in tactic.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        attack_id = ref.get("external_id")
                        break
                results.append(
                    {
                        "id": attack_id,
                        "name": tactic.get("name", ""),
                        "shortname": shortname,
                    }
                )

        return results

    def map_behavior_to_techniques(self, behavior: str, limit: int = 5) -> list[dict[str, Any]]:
        """Map a behavior description to likely ATT&CK techniques.

        This is a simple keyword-based matching. For production use,
        consider using ML-based mapping.

        Args:
            behavior: Description of observed behavior
            limit: Maximum techniques to return

        Returns:
            List of potentially matching techniques
        """
        # Common behavior keywords mapped to techniques
        keyword_mappings = {
            "powershell": ["T1059.001"],
            "cmd": ["T1059.003"],
            "bash": ["T1059.004"],
            "python": ["T1059.006"],
            "scheduled task": ["T1053.005"],
            "cron": ["T1053.003"],
            "registry": ["T1547.001", "T1112"],
            "dll": ["T1574.001", "T1574.002"],
            "process injection": ["T1055"],
            "credential dump": ["T1003"],
            "mimikatz": ["T1003.001"],
            "phishing": ["T1566"],
            "spearphishing": ["T1566.001", "T1566.002"],
            "lateral movement": ["T1021"],
            "rdp": ["T1021.001"],
            "ssh": ["T1021.004"],
            "smb": ["T1021.002"],
            "winrm": ["T1021.006"],
            "exfiltration": ["T1041"],
            "dns": ["T1071.004"],
            "http": ["T1071.001"],
            "c2": ["T1071"],
            "persistence": ["T1547"],
            "service": ["T1543.003"],
            "webshell": ["T1505.003"],
            "ransomware": ["T1486"],
            "encryption": ["T1486"],
        }

        behavior_lower = behavior.lower()
        matched_ids = set()

        for keyword, technique_ids in keyword_mappings.items():
            if keyword in behavior_lower:
                matched_ids.update(technique_ids)

        # Get full technique info for matches
        results = []
        for tid in list(matched_ids)[:limit]:
            technique = self.get_technique(tid)
            if technique:
                results.append(technique)

        # If no keyword matches, fall back to search
        if not results:
            results = self.search_techniques(behavior, limit=limit)

        return results
