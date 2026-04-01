"""Common parser sensitive arguments.

This module is kept dependency-free (no prowler-internal imports) so that
``prowler.lib.cli.redact`` and any provider argument module can import it
without circular-import risk.
"""

SENSITIVE_ARGUMENTS = frozenset({"--shodan"})
