from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client

ACTIVE_STATUSES = {"InProgress"}
# Markers that indicate the review targets directory role assignments (PIM roles).
PRIVILEGED_SCOPE_MARKERS = ("roledefinition", "rolemanagement", "roleassignment")


class entra_access_review_privileged_roles_configured(Check):
    """Check if an access review for privileged roles is configured and fail-closed.

    An access review scoped to privileged (PIM) directory roles should exist, be
    active, and be fail-closed: if reviewers do not respond, access is removed
    (``defaultDecision`` = Deny with ``autoApplyDecisionsEnabled``), with mail
    notifications and reminders enabled.

    - PASS: An active, fail-closed access review scoped to privileged roles exists.
    - FAIL: No such access review exists (missing, inactive, or not fail-closed).
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

    def _is_fail_closed(self, definition) -> bool:
        """Determine whether an access review definition is fail-closed.

        Args:
            definition: The access review definition to evaluate.

        Returns:
            bool: True if the review denies access by default, auto-applies
            decisions, and has mail notifications and reminders enabled.
        """
        return (
            definition.default_decision == "Deny"
            and definition.auto_apply_enabled
            and definition.mail_notifications_enabled
            and definition.reminders_enabled
        )

    def execute(self) -> List[CheckReportM365]:
        """Evaluate whether a fail-closed access review for privileged roles exists.

        Searches the tenant's access review definitions for an active, fail-closed
        review scoped to privileged (PIM) directory roles.

        Returns:
            List[CheckReportM365]: A single report indicating whether an active,
            fail-closed access review scoped to privileged roles is configured.
        """
        findings = []
        definitions = entra_client.access_review_definitions

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=definitions if definitions else {},
            resource_name="Access Review Definitions",
            resource_id="accessReviewDefinitions",
        )
        report.status = "FAIL"
        report.status_extended = (
            "No active fail-closed access review scoped to privileged roles is "
            "configured."
        )

        for definition in definitions:
            if (
                definition.status in ACTIVE_STATUSES
                and self._targets_privileged_roles(definition)
                and self._is_fail_closed(definition)
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
                    "privileged roles is active and fail-closed."
                )
                break

        findings.append(report)
        return findings
