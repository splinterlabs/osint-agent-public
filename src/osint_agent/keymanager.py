"""Secure API key management using system keychain."""

from __future__ import annotations

import logging
import os

import keyring

logger = logging.getLogger(__name__)

SERVICE_NAME = "osint-agent"

# Key identifiers
KEYS = {
    "NVD_API_KEY": "nvd",
    "OTX_API_KEY": "otx",
    "VT_API_KEY": "virustotal",
    "ABUSEIPDB_API_KEY": "abuseipdb",
    "SHODAN_API_KEY": "shodan",
    "ABUSECH_AUTH_KEY": "abusech",
    "FRESHRSS_URL": "freshrss_url",
    "FRESHRSS_USERNAME": "freshrss_username",
    "FRESHRSS_PASSWORD": "freshrss_password",
}


def get_api_key(key_name: str) -> str | None:
    """Retrieve API key from secure storage or environment.

    Order of precedence:
    1. Environment variable (for CI/containers)
    2. System keychain
    """
    # 1. Check environment variable first
    env_value = os.environ.get(key_name)
    if env_value:
        return env_value

    # 2. Check system keychain
    service_key = KEYS.get(key_name)
    if service_key:
        try:
            value: str | None = keyring.get_password(SERVICE_NAME, service_key)
            if value:
                return value
        except keyring.errors.KeyringError as e:
            logger.warning(f"Keyring error retrieving {key_name}: {e}")

    return None


def set_api_key(key_name: str, value: str) -> bool:
    """Store API key in system keychain."""
    service_key = KEYS.get(key_name)
    if not service_key:
        logger.error(f"Unknown key: {key_name}. Valid keys: {list(KEYS.keys())}")
        return False

    if not value or not value.strip():
        logger.error(f"Refusing to store empty value for {key_name}")
        return False

    try:
        keyring.set_password(SERVICE_NAME, service_key, value)
        logger.info(f"Stored {key_name} in system keychain")
        return True
    except keyring.errors.KeyringError as e:
        logger.error(f"Failed to store {key_name}: {e}")
        return False


def delete_api_key(key_name: str) -> bool:
    """Remove API key from system keychain."""
    service_key = KEYS.get(key_name)
    if not service_key:
        logger.error(f"Unknown key: {key_name}")
        return False

    try:
        keyring.delete_password(SERVICE_NAME, service_key)
        logger.info(f"Deleted {key_name} from system keychain")
        return True
    except keyring.errors.KeyringError as e:
        logger.warning(f"Failed to delete {key_name}: {e}")
        return False


def is_key_configured(key_name: str) -> bool:
    """Check whether an API key is configured without loading its value.

    Checks environment variables first, then the system keychain.
    """
    if os.environ.get(key_name):
        return True

    service_key = KEYS.get(key_name)
    if service_key:
        try:
            return keyring.get_password(SERVICE_NAME, service_key) is not None
        except keyring.errors.KeyringError:
            return False

    return False


def list_configured_keys() -> dict[str, bool]:
    """List which API keys are configured."""
    return {key_name: is_key_configured(key_name) for key_name in KEYS}


def print_key_status() -> None:
    """Print status of all API keys to stdout.

    Note: This function prints to stdout for CLI usage.
    """
    status = list_configured_keys()
    for key_name, configured in status.items():
        symbol = "✓" if configured else "✗"
        state = "configured" if configured else "not configured"
        print(f"{symbol} {key_name}: {state}")  # noqa: T201 - Intentional CLI output
