"""Shared test fixtures."""

import os

# Disable API response caching during tests so mocked HTTP calls are always made.
os.environ["OSINT_NO_CACHE"] = "1"
