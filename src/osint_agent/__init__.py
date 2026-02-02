"""OSINT Agent - Cyber security intelligence gathering with Claude Code hooks."""

__version__ = "0.1.0"

from .extractors import extract_iocs
from .cpe import WatchlistMatcher, match_cpe_pattern
from .campaigns import Campaign, CampaignManager, CampaignStatus
from .correlation import CorrelationEngine

__all__ = [
    "__version__",
    "extract_iocs",
    "WatchlistMatcher",
    "match_cpe_pattern",
    "Campaign",
    "CampaignManager",
    "CampaignStatus",
    "CorrelationEngine",
]
