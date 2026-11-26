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


def _top_level_disjuncts(expression: str) -> list[str]:
    """Split a normalized expression on the ``or`` / ``||`` operators outside parentheses and strings."""
    parts = []
    depth = 0
    in_string = False
    start = 0
    index = 0
    while index < len(expression):
        char = expression[index]
        if in_string:
            if char == "\\":
                index += 1
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0:
            for operator in (" or ", " || "):
                if expression.startswith(operator, index):
                    parts.append(expression[start:index])
                    index += len(operator)
                    start = index
                    break
            else:
                index += 1
            continue
        index += 1
    parts.append(expression[start:])
    return parts


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
    if any(pattern.match(normalized) for pattern in MATCH_ALL_PATTERNS):
        return True
    disjuncts = _top_level_disjuncts(normalized)
    return len(disjuncts) > 1 and any(
        matches_all_traffic(disjunct) for disjunct in disjuncts if disjunct.strip()
    )
