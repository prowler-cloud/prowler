"""Helpers to evaluate the action configured for Gmail spoofing protections."""

from typing import Optional

# Actions that actually keep the message away from the inbox. CIS Google
# Workspace 3.1.3.4.3.1, 3.1.3.4.3.2, 3.1.3.4.3.3 and 3.1.3.4.3.5 all require
# the action to be "Move email to spam"; quarantining is stricter and also
# satisfies the recommendation.
PROTECTIVE_CONSEQUENCES = {"SPAM_FOLDER", "QUARANTINE"}

# Google leaves these protections enabled but set to "Keep email in inbox and
# show warning", which the benchmark does not accept, so an unset action is
# evaluated as the insecure default rather than as a secure one.
UNSET_CONSEQUENCE_DESCRIPTION = (
    "uses Google's default action (keep email in inbox and show a warning)"
)

CONSEQUENCE_DESCRIPTIONS = {
    "NO_ACTION": "is set to take no action",
    "WARNING": "is set to keep the email in the inbox and show a warning",
}


def describe_consequence(consequence: Optional[str]) -> str:
    """Return a human-readable description of a non-protective action."""
    if consequence is None:
        return UNSET_CONSEQUENCE_DESCRIPTION
    return CONSEQUENCE_DESCRIPTIONS.get(consequence, f"is set to '{consequence}'")


def is_protective(consequence: Optional[str]) -> bool:
    """Whether the configured action moves the message out of the inbox."""
    return consequence in PROTECTIVE_CONSEQUENCES
