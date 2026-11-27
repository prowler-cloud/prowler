MAX_LISTED_VULNERABILITIES = 10


def summarize_vulnerabilities(vulnerabilities: list[str]) -> str:
    """Join vulnerability identifiers, truncating long lists."""
    listed = ", ".join(vulnerabilities[:MAX_LISTED_VULNERABILITIES])
    remaining = len(vulnerabilities) - MAX_LISTED_VULNERABILITIES
    return f"{listed} and {remaining} more" if remaining > 0 else listed
