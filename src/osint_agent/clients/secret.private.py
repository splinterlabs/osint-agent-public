"""Secret client - tests *.private.* exclusion pattern."""

INTERNAL_SECRET = "this-tests-the-private-pattern"

class SecretClient:
    """This should never be synced."""
    pass
