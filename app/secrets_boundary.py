"""Dummy-only secret sentinel, isolated from tool data and model context.

No environment or credential files are read. This is an educational export guard,
not general secret discovery or protection from arbitrary local Python execution.
"""

_DUMMY_SECRET = "LAB_DUMMY_SECRET_NEVER_EXPORT"


def contains_dummy_secret(text: str) -> bool:
    """Check without returning the dummy value to the caller."""
    return _DUMMY_SECRET in text
