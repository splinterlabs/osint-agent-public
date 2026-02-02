"""Context management system with 5-tier hierarchy.

Implements TSUKUYOMI-style context management for maintaining analytical state
across sessions and investigations.

Tiers:
1. STRATEGIC - Long-term objectives, threat landscape trends (persistent)
2. OPERATIONAL - Current investigation scope, stakeholder requirements (project-level)
3. TACTICAL - Immediate priorities, active module states, working IOCs (session-level)
4. TECHNICAL - API parameters, query specifications, tool configurations
5. SECURITY - Data handling rules, source sensitivity, sharing boundaries
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ContextManager:
    """Manages 5-tier context hierarchy for intelligence analysis."""

    TIERS = ["strategic", "operational", "tactical", "technical", "security"]

    def __init__(self, context_dir: Path | str):
        self.context_dir = Path(context_dir)
        self.context_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, dict[str, Any]] = {}

    def _context_path(self, tier: str) -> Path:
        """Get path for a context tier file."""
        return self.context_dir / f"{tier}_context.json"

    def _load_tier(self, tier: str) -> dict[str, Any]:
        """Load a context tier from disk."""
        if tier in self._cache:
            return self._cache[tier]

        path = self._context_path(tier)
        if not path.exists():
            default = self._default_context(tier)
            self._save_tier(tier, default)
            return default

        try:
            with open(path) as f:
                data: dict[str, Any] = json.load(f)
                self._cache[tier] = data
                return data
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Failed to load {tier} context: {e}")
            return self._default_context(tier)

    def _save_tier(self, tier: str, data: dict[str, Any]) -> None:
        """Save a context tier to disk with secure permissions (atomic write).

        SECURITY: Sets restrictive file permissions (0600) to prevent unauthorized access.
        Context files may contain sensitive investigation data and IOCs.
        """
        path = self._context_path(tier)
        data["last_modified"] = datetime.now(UTC).isoformat()

        # Create temp file with secure permissions
        old_umask = os.umask(0o077)  # Ensure temp file is created with 600
        try:
            fd, tmp_path = tempfile.mkstemp(
                dir=self.context_dir,
                prefix=f".{tier}_",
                suffix=".json.tmp",
            )
        finally:
            os.umask(old_umask)  # Restore original umask

        try:
            with open(fd, "w") as f:
                json.dump(data, f, indent=2, default=str)

            # Explicitly set restrictive permissions (owner read/write only)
            os.chmod(tmp_path, 0o600)

            # Atomic rename
            os.replace(tmp_path, path)

            # Verify final file permissions (defense in depth)
            os.chmod(path, 0o600)
        except Exception:
            Path(tmp_path).unlink(missing_ok=True)
            raise

        self._cache[tier] = data

    def _default_context(self, tier: str) -> dict[str, Any]:
        """Get default context for a tier."""
        base = {
            "tier": tier,
            "created": datetime.now(UTC).isoformat(),
            "last_modified": datetime.now(UTC).isoformat(),
        }

        if tier == "strategic":
            return {
                **base,
                "objectives": [],
                "threat_landscape": {
                    "priority_threats": [],
                    "trends": [],
                    "notes": "",
                },
                "campaigns": [],
            }

        elif tier == "operational":
            return {
                **base,
                "investigation": {
                    "name": "",
                    "description": "",
                    "stakeholders": [],
                    "scope": "",
                    "status": "not_started",
                },
                "requirements": [],
                "deliverables": [],
            }

        elif tier == "tactical":
            return {
                **base,
                "priorities": [],
                "active_iocs": [],
                "working_hypotheses": [],
                "findings": [],
                "next_steps": [],
                "usage_stats": {},
            }

        elif tier == "technical":
            return {
                **base,
                "api_configs": {},
                "query_templates": {},
                "tool_settings": {},
            }

        elif tier == "security":
            return {
                **base,
                "classification": "unclassified",
                "handling_caveats": [],
                "sharing_restrictions": [],
                "source_sensitivity": {},
            }

        return base

    def get(self, tier: str, key: str | None = None) -> Any:
        """Get context data.

        Args:
            tier: Context tier (strategic/operational/tactical/technical/security)
            key: Optional specific key to retrieve

        Returns:
            Full tier data or specific key value
        """
        if tier not in self.TIERS:
            raise ValueError(f"Invalid tier: {tier}. Must be one of {self.TIERS}")

        data = self._load_tier(tier)

        if key is None:
            return data
        return data.get(key)

    def set(self, tier: str, key: str, value: Any) -> None:
        """Set a context value.

        Args:
            tier: Context tier
            key: Key to set
            value: Value to set
        """
        if tier not in self.TIERS:
            raise ValueError(f"Invalid tier: {tier}. Must be one of {self.TIERS}")

        data = self._load_tier(tier)
        data[key] = value
        self._save_tier(tier, data)

    def update(self, tier: str, updates: dict[str, Any]) -> None:
        """Update multiple context values.

        Args:
            tier: Context tier
            updates: Dict of key-value pairs to update
        """
        if tier not in self.TIERS:
            raise ValueError(f"Invalid tier: {tier}. Must be one of {self.TIERS}")

        data = self._load_tier(tier)
        data.update(updates)
        self._save_tier(tier, data)

    def append(self, tier: str, key: str, value: Any) -> None:
        """Append to a list in context.

        Args:
            tier: Context tier
            key: Key of list to append to
            value: Value to append
        """
        data = self._load_tier(tier)
        if key not in data:
            data[key] = []
        if not isinstance(data[key], list):
            raise ValueError(f"{key} is not a list")

        data[key].append(value)
        self._save_tier(tier, data)

    def get_all(self) -> dict[str, dict[str, Any]]:
        """Get all context tiers."""
        return {tier: self._load_tier(tier) for tier in self.TIERS}

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of current context state."""
        all_ctx = self.get_all()

        return {
            "strategic": {
                "objective_count": len(all_ctx["strategic"].get("objectives", [])),
                "priority_threats": all_ctx["strategic"].get("threat_landscape", {}).get(
                    "priority_threats", []
                )[:5],
            },
            "operational": {
                "investigation": all_ctx["operational"].get("investigation", {}).get(
                    "name", ""
                ),
                "status": all_ctx["operational"].get("investigation", {}).get(
                    "status", "not_started"
                ),
            },
            "tactical": {
                "priority_count": len(all_ctx["tactical"].get("priorities", [])),
                "active_ioc_count": len(all_ctx["tactical"].get("active_iocs", [])),
                "finding_count": len(all_ctx["tactical"].get("findings", [])),
                "usage_stats": all_ctx["tactical"].get("usage_stats", {}),
            },
            "security": {
                "classification": all_ctx["security"].get(
                    "classification", "unclassified"
                ),
            },
        }

    def clear_tier(self, tier: str) -> None:
        """Reset a tier to defaults."""
        if tier not in self.TIERS:
            raise ValueError(f"Invalid tier: {tier}. Must be one of {self.TIERS}")

        default = self._default_context(tier)
        self._save_tier(tier, default)

    def start_investigation(
        self,
        name: str,
        description: str = "",
        scope: str = "",
        stakeholders: list[str] | None = None,
    ) -> None:
        """Start a new investigation (resets operational and tactical).

        Args:
            name: Investigation name
            description: Investigation description
            scope: Investigation scope
            stakeholders: List of stakeholders
        """
        # Reset operational context
        self.clear_tier("operational")
        self.update(
            "operational",
            {
                "investigation": {
                    "name": name,
                    "description": description,
                    "scope": scope,
                    "stakeholders": stakeholders or [],
                    "status": "in_progress",
                    "started": datetime.now(UTC).isoformat(),
                }
            },
        )

        # Reset tactical context
        self.clear_tier("tactical")

    def add_ioc(
        self,
        ioc_type: str,
        value: str,
        confidence: float = 0.5,
        source: str = "",
        tags: list[str] | None = None,
    ) -> None:
        """Add an IOC to tactical context.

        Args:
            ioc_type: Type of IOC (ipv4, domain, hash, etc.)
            value: IOC value
            confidence: Confidence level (0-1)
            source: Source of the IOC
            tags: Optional tags
        """
        ioc = {
            "type": ioc_type,
            "value": value,
            "confidence": confidence,
            "source": source,
            "tags": tags or [],
            "added": datetime.now(UTC).isoformat(),
        }
        self.append("tactical", "active_iocs", ioc)

    def add_finding(
        self,
        title: str,
        description: str,
        confidence: float = 0.5,
        evidence: list[str] | None = None,
    ) -> None:
        """Add a finding to tactical context.

        Args:
            title: Finding title
            description: Finding description
            confidence: Confidence level (0-1)
            evidence: Supporting evidence references
        """
        finding = {
            "title": title,
            "description": description,
            "confidence": confidence,
            "evidence": evidence or [],
            "timestamp": datetime.now(UTC).isoformat(),
        }
        self.append("tactical", "findings", finding)
