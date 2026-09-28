from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client

ACTIVE_STATUSES = {"InProgress"}
ALLOWED_RECURRENCE_PATTERNS = {"weekly", "absoluteMonthly"}
# Markers that indicate the review targets directory role assignments (PIM roles).
PRIVILEGED_SCOPE_MARKERS = ("roledefinition", "rolemanagement", "roleassignment")


class entra_access_review_privileged_roles_configured(Check):
    """Check if a compliant recurring access review for privileged roles exists.

    An access review scoped to privileged (PIM) directory roles should exist, be
    active, recurring, and have primary reviewers assigned. It should use
    ``defaultDecision`` = None with ``autoApplyDecisionsEnabled``, mail
    notifications, and reminders enabled.

    - PASS: A compliant recurring access review scoped to privileged roles exists.
    - FAIL: No compliant recurring access review scoped to privileged roles exists.
    """

    def _targets_privileged_roles(self, definition) -> bool:
        """Determine whether an access review targets privileged directory roles.

        For PIM role reviews the role reference lives in the resource scopes, so both
        the scope query and the resource scope queries are inspected for markers that
        indicate directory role assignments.

        Args:
            definition: The access review definition to evaluate.

        Returns:
            bool: True if any of the review's scope queries reference privileged
            (PIM) directory roles.
        """
        queries = [definition.scope_query] + definition.resource_scope_queries
        return any(
            marker in query.lower()
            for query in queries
            for marker in PRIVILEGED_SCOPE_MARKERS
        )

    def _has_required_decision_settings(self, definition) -> bool:
        """Determine whether an access review has the required decision settings.

        Args:
            definition: The access review definition to evaluate.

        Returns:
            bool: True if the review makes no default decision, auto-applies
            decisions, and has mail notifications and reminders enabled.
        """
        return (
            definition.default_decision == "None"
            and definition.auto_apply_enabled
            and definition.mail_notifications_enabled
            and definition.reminders_enabled
        )

    def _is_recurring_with_reviewers(self, definition) -> bool:
        """Determine whether recurrence and primary reviewers are configured."""
        return (
            definition.recurrence_pattern_type in ALLOWED_RECURRENCE_PATTERNS
            and definition.recurrence_range_type == "noEnd"
            and definition.has_primary_reviewers
        )

    def execute(self) -> List[CheckReportM365]:
        """Evaluate whether a compliant access review for privileged roles exists.

        Searches the tenant's access review definitions for an active, recurring,
        reviewer-assigned review scoped to privileged (PIM) directory roles.

        Returns:
            List[CheckReportM365]: A single report indicating whether a compliant
            access review scoped to privileged roles is configured.
        """
        findings = []
        definitions = entra_client.access_review_definitions

        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Access Review Definitions",
            resource_id="accessReviewDefinitions",
        )
        report.status = "FAIL"
        report.status_extended = (
            "No compliant recurring access review scoped to privileged roles is "
            "configured with assigned primary reviewers."
        )

        for definition in definitions:
            if (
                definition.status in ACTIVE_STATUSES
                and self._targets_privileged_roles(definition)
                and self._has_required_decision_settings(definition)
                and self._is_recurring_with_reviewers(definition)
            ):
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=definition,
                    resource_name=definition.display_name or "Access Review",
                    resource_id=definition.id,
                )
                report.status = "PASS"
                report.status_extended = (
                    f"Access review '{definition.display_name or definition.id}' for "
                    "privileged roles is active, recurring, reviewer-assigned, and "
                    "configured with no default decision."
                )
                break

        findings.append(report)
        return findings
