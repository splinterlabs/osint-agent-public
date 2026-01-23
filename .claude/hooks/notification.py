#!/usr/bin/env python3
"""Notification hook - Alert on critical security findings."""

import json
import logging
import subprocess
import sys
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Project root is 3 levels up from .claude/hooks/
PROJECT_ROOT = Path(__file__).parent.parent.parent

# Configuration
ALERT_LOG_PATH = PROJECT_ROOT / "data" / "logs" / "alerts.jsonl"

CRITICAL_KEYWORDS = [
    "cvss 9",
    "cvss 10",
    "actively exploited",
    "zero-day",
    "0-day",
    "critical vulnerability",
    "ransomware",
    "apt",
    "nation-state",
    "in the wild",
    "proof of concept",
    "poc available",
    "rce",
    "remote code execution",
    "authentication bypass",
    "cisa kev",
]


def send_desktop_notification(title: str, message: str, urgency: str = "normal") -> bool:
    """Send desktop notification (macOS/Linux)."""
    try:
        # macOS
        if sys.platform == "darwin":
            subprocess.run(
                [
                    "osascript",
                    "-e",
                    f'display notification "{message}" with title "{title}"',
                ],
                check=True,
                capture_output=True,
            )
            return True

        # Linux (requires notify-send)
        elif sys.platform.startswith("linux"):
            urgency_flag = "critical" if urgency == "critical" else "normal"
            subprocess.run(
                ["notify-send", "-u", urgency_flag, title, message],
                check=True,
                capture_output=True,
            )
            return True

    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.warning(f"Desktop notification failed: {e}")

    return False


def log_alert(message: str, level: str) -> None:
    """Log alert to JSONL file."""
    ALERT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "level": level,
        "message": message[:500],  # Truncate long messages
    }

    with open(ALERT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def check_critical(message: str) -> bool:
    """Check if message contains critical indicators."""
    message_lower = message.lower()
    return any(keyword in message_lower for keyword in CRITICAL_KEYWORDS)


def main() -> None:
    """Hook entry point."""
    try:
        hook_input = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        logger.error("Invalid JSON input")
        return

    message = hook_input.get("message", "")
    level = hook_input.get("level", "info")

    # Determine if critical
    is_critical = level == "critical" or check_critical(message)

    if is_critical:
        # Send desktop notification
        send_desktop_notification(
            title="🚨 Security Alert",
            message=message[:200],
            urgency="critical",
        )

        # Log alert
        log_alert(message, "critical")

        logger.info(f"Critical alert triggered: {message[:100]}")

    elif level in ("warning", "high"):
        log_alert(message, level)


if __name__ == "__main__":
    main()
