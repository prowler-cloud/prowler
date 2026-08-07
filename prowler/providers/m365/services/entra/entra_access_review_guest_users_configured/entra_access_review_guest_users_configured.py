from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client

ACTIVE_STATUSES = {"InProgress"}


class entra_access_review_guest_users_configured(Check):
    """Check if an access review for guest users is configured and fail-closed.

    An access review scoped to guest users should exist, be active, and be
    fail-closed: if reviewers do not respond, access is removed
    (``defaultDecision`` = Deny with ``autoApplyDecisionsEnabled``), with mail
    notifications and reminders enabled.

    - PASS: An active, fail-closed access review scoped to guest users exists.
    - FAIL: No such access review exists (missing, inactive, or not fail-closed).
    """

    def _targets_guest_users(self, definition) -> bool:
        """Determine whether an access review targets guest users.

        Portal-created reviews use a principal-resource-memberships scope where the
        guest filter (``userType eq 'Guest'``) lives in the principal scopes and the
        top-level scope query is empty, so both are inspected.

        Args:
            definition: The access review definition to evaluate.

        Returns:
            bool: True if any of the review's scope queries reference guest users.
        """
        queries = [definition.scope_query] + definition.principal_scope_queries
        return any("guest" in query.lower() for query in queries)

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
        """Evaluate whether a fail-closed access review for guest users exists.

        Searches the tenant's access review definitions for an active, fail-closed
        review scoped to guest users.

        Returns:
            List[CheckReportM365]: A single report indicating whether an active,
            fail-closed access review scoped to guest users is configured.
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
            "No active fail-closed access review scoped to guest users is configured."
        )

        for definition in definitions:
            if (
                definition.status in ACTIVE_STATUSES
                and self._targets_guest_users(definition)
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
                    "guest users is active and fail-closed."
                )
                break

        findings.append(report)
        return findings
