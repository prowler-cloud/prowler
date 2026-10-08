"""Check that dynamic membership groups do not use the retiring memberOf rule operator."""

import re
from datetime import date
from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client

# Pre-compiled patterns -------------------------------------------------
# After stripping quoted literals, detect the memberOf property reference.
_MEMBEROF_PROPERTY_RE = re.compile(r"(?i)\b(user|device)\.memberof\b")

# Extract GUIDs that appear in a memberOf expression (on the original rule).
_GUID_RE = re.compile(r"(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b")

# Matches single- or double-quoted string literals to strip before detection.
_QUOTED_LITERAL_RE = re.compile(r"""('[^']*'|"[^"]*")""")

# The date Microsoft retires the memberOf preview operator.
_RETIREMENT_DATE = date(2026, 11, 3)


def _rule_uses_memberof(rule: str) -> bool:
    """Return True if *rule* references the memberOf property outside quoted literals.

    Stripping quoted strings first avoids false positives like
    ``user.department -eq "user.memberOf"``.
    """
    stripped = _QUOTED_LITERAL_RE.sub("", rule)
    return bool(_MEMBEROF_PROPERTY_RE.search(stripped))


def _extract_source_group_ids(rule: str) -> List[str]:
    """Return deduplicated GUIDs found after a memberOf reference in the original rule.

    GUIDs are collected from the full (unstripped) rule and deduplicated
    case-insensitively while preserving the original casing.
    """
    # Find the position of the first memberOf property reference.
    match = _MEMBEROF_PROPERTY_RE.search(rule)
    if not match:
        return []

    after_memberof = rule[match.end() :]
    seen: set = set()
    result: list = []
    for guid_match in _GUID_RE.finditer(after_memberof):
        guid = guid_match.group()
        lower = guid.lower()
        if lower not in seen:
            seen.add(lower)
            result.append(guid)
    return result


class entra_dynamic_group_member_of_rule_not_used(Check):
    """Ensure dynamic membership groups do not use the retiring memberOf rule operator.

    This check evaluates every Entra ID group whose ``groupTypes`` contains
    ``DynamicMembership``.  The ``memberOf`` operator
    (``user.memberof`` / ``device.memberof``) is a public preview that
    Microsoft is ending on November 3, 2026.  After that date, dynamic groups
    still using the operator stop updating and stay frozen in their last known
    membership, creating a silent access-control gap.

    - PASS: The dynamic group's membership rule does not reference the
      ``memberOf`` property.
    - FAIL: The dynamic group's membership rule references ``user.memberof``
      or ``device.memberof``.
    - MANUAL: Groups could not be read (permissions, throttling, API error),
      or a dynamic group has a null/empty membership rule that could not be
      evaluated.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the memberOf rule check for all dynamic membership groups.

        Returns:
            A list of reports, one per dynamic membership group evaluated.
        """
        findings: List[CheckReportM365] = []

        # If groups could not be retrieved, emit a single tenant-level MANUAL.
        if entra_client.groups_error:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Dynamic groups",
                resource_id="groups",
            )
            report.status = "MANUAL"
            report.status_extended = (
                f"Cannot evaluate dynamic group memberOf rules: "
                f"{entra_client.groups_error}."
            )
            findings.append(report)
            return findings

        today = date.today()

        for group in entra_client.groups:
            if "DynamicMembership" not in group.groupTypes:
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=group,
                resource_name=group.name,
                resource_id=group.id,
            )

            # A null/empty membership rule cannot be evaluated.
            if not group.membershipRule:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Dynamic group {group.name} has no membership rule; "
                    f"the rule could not be read."
                )
                findings.append(report)
                continue

            # Normalise CR/LF to spaces for matching.
            normalised_rule = group.membershipRule.replace("\r", " ").replace("\n", " ")

            if _rule_uses_memberof(normalised_rule):
                processing_state = group.membership_rule_processing_state or "Unknown"
                source_ids = _extract_source_group_ids(normalised_rule)
                source_ids_text = (
                    f" referencing source group(s): {', '.join(source_ids)}"
                    if source_ids
                    else ""
                )

                if today < _RETIREMENT_DATE:
                    retirement_text = "is being retired on November 3, 2026"
                else:
                    retirement_text = (
                        "was retired on November 3, 2026 and the group "
                        "membership may already be stale"
                    )

                report.status = "FAIL"
                report.status_extended = (
                    f"Dynamic group {group.name} (processing: {processing_state}) "
                    f"uses the memberOf rule operator which {retirement_text}"
                    f"{source_ids_text}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Dynamic group {group.name} does not use the memberOf "
                    f"rule operator."
                )

            findings.append(report)

        return findings
