"""Helpers for evaluating Cloudflare Rules language expressions."""

import re

# Expressions that match every request. A Rules language expression is
# normalized (lowercase, collapsed whitespace, outer parentheses removed)
# before being compared.
MATCH_ALL_EXPRESSIONS = {
    "true",
    "not false",
    # Every HTTPS request; all traffic when "Always Use HTTPS" is enabled.
    "ssl",
}
MATCH_ALL_PATTERNS = (
    # any field matched with a bare wildcard / regex that accepts everything
    re.compile(r'^[a-z0-9_.\[\]"*]+ wildcard "\*"$'),
    re.compile(r'^[a-z0-9_.\[\]"*]+ (matches|~) "(\^)?\.\*(\$)?"$'),
    # every request path starts with or contains "/"
    re.compile(r'^http\.request\.uri\.path (contains|starts_with) "/"$'),
    # every IPv4 and/or IPv6 source address
    re.compile(r"^ip\.src in \{\s*(0\.0\.0\.0/0|::/0)(\s+(0\.0\.0\.0/0|::/0))?\s*\}$"),
)


def _normalize(expression: str) -> str:
    expression = re.sub(r"\s+", " ", (expression or "").strip().lower())
    while expression.startswith("(") and expression.endswith(")"):
        inner = expression[1:-1].strip()
        # only strip parentheses that wrap the whole expression
        depth = 0
        balanced = True
        for char in inner:
            depth += char == "("
            depth -= char == ")"
            if depth < 0:
                balanced = False
                break
        if not balanced or depth != 0:
            break
        expression = inner
    return expression


def matches_all_traffic(expression: str) -> bool:
    """Return True when a Rules language expression matches every request.

    Args:
        expression: The rule expression.

    Returns:
        Whether the expression is unconditional.
    """
    normalized = _normalize(expression)
    if not normalized or normalized in MATCH_ALL_EXPRESSIONS:
        return True
    return any(pattern.match(normalized) for pattern in MATCH_ALL_PATTERNS)
