"""
Cypher sanitizer for custom (user-supplied) Attack Paths queries.

Two responsibilities:

1. **Validation** - reject queries containing SSRF or dangerous procedure
   patterns (defense-in-depth; the primary control is `neo4j.READ_ACCESS`).

2. **Provider-scoped label injection** - inject a dynamic
   `_Provider_{uuid}` label into every node pattern so the database can
   use its native label index for provider isolation.

Label-injection pipeline:

1. **Protect** string literals and line comments (placeholder replacement).
2. **Split** by top-level clause keywords to track clause context.
3. **Pass A** - inject into *labeled* node patterns in ALL segments.
4. **Pass B** - inject into *bare* node patterns in MATCH segments only.
5. **Restore** protected regions.
"""

import re

from rest_framework.exceptions import ValidationError

from tasks.jobs.attack_paths.config import get_provider_label


# Step 1 - String / comment protection
# Single combined regex: strings first, then line comments.
# The regex engine finds the leftmost match, so a string like 'https://prowler.com'
# is consumed as a string before the // inside it can match as a comment.
_PROTECTED_RE = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|//[^\n]*")

# Step 2 - Clause splitting
# OPTIONAL MATCH must come before MATCH to avoid partial matching.
_CLAUSE_RE = re.compile(
    r"\b(OPTIONAL\s+MATCH|MATCH|WHERE|RETURN|WITH|ORDER\s+BY"
    r"|SKIP|LIMIT|UNION|UNWIND|CALL)\b",
    re.IGNORECASE,
)

# Pass A - Labeled node patterns (all segments)
# Matches node patterns that have at least one :Label.
# (?<!\w)\(  - open paren NOT preceded by a word char (excludes function calls).
# Group 1:  optional variable + one or more :Label
# Group 2:  optional {properties} + closing paren
_LABELED_NODE_RE = re.compile(
    r"(?<!\w)\("
    r"("
    r"\s*(?:[a-zA-Z_]\w*)?"
    r"(?:\s*:\s*(?:`[^`]*`|[a-zA-Z_]\w*))+"
    r")"
    r"("
    r"\s*(?:\{[^}]*\})?"
    r"\s*\)"
    r")"
)

# Pass B - Bare node patterns (MATCH segments only)
# Matches (identifier) or (identifier {properties}) without any :Label.
# Only applied in MATCH/OPTIONAL MATCH segments.
_BARE_NODE_RE = re.compile(
    r"(?<!\w)\(" r"(\s*[a-zA-Z_]\w*)" r"(\s*(?:\{[^}]*\})?)" r"\s*\)"
)

_MATCH_CLAUSES = frozenset({"MATCH", "OPTIONAL MATCH"})


def _inject_labeled(segment: str, label: str) -> str:
    """Inject provider label into all node patterns that have existing labels."""
    return _LABELED_NODE_RE.sub(rf"(\1:{label}\2", segment)


def _inject_bare(segment: str, label: str) -> str:
    """Inject provider label into bare `(identifier)` node patterns."""

    def _replace(match):
        var = match.group(1)
        props = match.group(2).strip()
        if props:
            return f"({var}:{label} {props})"
        return f"({var}:{label})"

    return _BARE_NODE_RE.sub(_replace, segment)


def inject_provider_label(cypher: str, provider_id: str) -> str:
    """Rewrite a Cypher query to scope every node pattern to a provider.

    Args:
        cypher: The original Cypher query string.
        provider_id: The provider UUID (will be converted to a label via
            `get_provider_label`).

    Returns:
        The rewritten Cypher with `:_Provider_{uuid}` appended to every
        node pattern.
    """
    label = get_provider_label(provider_id)

    # Step 1: Protect strings and comments (single pass, leftmost-first)
    protected: list[str] = []

    def _save(match):
        protected.append(match.group(0))
        return f"\x00P{len(protected) - 1}\x00"

    work = _PROTECTED_RE.sub(_save, cypher)

    # Step 2: Split by clause keywords
    parts = _CLAUSE_RE.split(work)

    # Steps 3-4: Apply injection passes per segment
    result: list[str] = []
    current_clause: str | None = None

    for i, part in enumerate(parts):
        if i % 2 == 1:
            # Keyword token - normalize for clause tracking
            current_clause = re.sub(r"\s+", " ", part.strip()).upper()
            result.append(part)
        else:
            # Content segment - apply injection based on clause context
            part = _inject_labeled(part, label)
            if current_clause in _MATCH_CLAUSES:
                part = _inject_bare(part, label)
            result.append(part)

    work = "".join(result)

    # Step 5: Restore protected regions
    for i, original in enumerate(protected):
        work = work.replace(f"\x00P{i}\x00", original)

    return work


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

# Patterns that indicate SSRF or dangerous procedure calls
# Defense-in-depth layer - the primary control is `neo4j.READ_ACCESS`
_BLOCKED_PATTERNS = [
    re.compile(r"\bLOAD\s+CSV\b", re.IGNORECASE),
    re.compile(r"\bapoc\.load\b", re.IGNORECASE),
    re.compile(r"\bapoc\.import\b", re.IGNORECASE),
    re.compile(r"\bapoc\.export\b", re.IGNORECASE),
    re.compile(r"\bapoc\.cypher\b", re.IGNORECASE),
    re.compile(r"\bapoc\.systemdb\b", re.IGNORECASE),
    re.compile(r"\bapoc\.config\b", re.IGNORECASE),
    re.compile(r"\bapoc\.periodic\b", re.IGNORECASE),
    re.compile(r"\bapoc\.do\b", re.IGNORECASE),
    re.compile(r"\bapoc\.trigger\b", re.IGNORECASE),
    re.compile(r"\bapoc\.custom\b", re.IGNORECASE),
]


def validate_custom_query(cypher: str) -> None:
    """Reject queries containing known SSRF or dangerous procedure patterns.

    Raises ValidationError if a blocked pattern is found.
    String literals and comments are stripped before matching to avoid
    false positives.
    """
    stripped = _PROTECTED_RE.sub("", cypher)
    for pattern in _BLOCKED_PATTERNS:
        if pattern.search(stripped):
            raise ValidationError({"query": "Query contains a blocked operation"})
