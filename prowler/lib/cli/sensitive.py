"""Common parser sensitive arguments.

This module is kept dependency-free (no prowler-internal imports) so that
both ``prowler.lib.cli.parser`` and ``prowler.lib.cli.redact`` can import
it without circular-import risk.
"""

SENSITIVE_ARGUMENTS = frozenset({"--shodan"})
