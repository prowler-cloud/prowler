import re
from typing import List
from urllib.parse import unquote

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client

ACTIVE_STATUSES = {"InProgress"}
ALLOWED_RECURRENCE_PATTERNS = {"weekly", "absoluteMonthly"}
GUEST_USER_PREDICATE = re.compile(r"\busertype\s+eq\s+(['\"])guest\1", re.IGNORECASE)
NEGATED_GUEST_USER_PREDICATE = re.compile(
    r"\bnot\s*\(\s*usertype\s+eq\s+(['\"])guest\1\s*\)", re.IGNORECASE
)


class entra_access_review_guest_users_configured(Check):
    """Check if an access review for guest users is configured and fail-closed.

    An access review scoped to guest users should exist, be active, recurring,
    and have primary reviewers assigned. It should also be fail-closed: if
    reviewers do not respond, access is removed
    (``defaultDecisionEnabled`` with ``defaultDecision`` = Deny and
    ``autoApplyDecisionsEnabled``), with mail notifications and reminders enabled.

    - PASS: A compliant recurring access review scoped to guest users exists.
    - FAIL: No compliant recurring access review scoped to guest users exists.
    """

    def _targets_guest_users(self, definition) -> bool:
        """Determine whether an access review targets guest users.

        Portal-created reviews use a principal-resource-memberships scope where the
        guest filter (``userType eq 'Guest'``) lives in the principal scopes and the
        top-level scope query is empty, so both are inspected.

        This bounded matcher recognizes the equality predicate and its direct
        ``not(...)`` negation. It does not interpret other compound or nested OData
        boolean semantics.

        Args:
            definition: The access review definition to evaluate.

        Returns:
            bool: True if any scope contains the guest-user equality predicate.
        """
        queries = [definition.scope_query] + definition.principal_scope_queries
        for query in queries:
            decoded_query = unquote(query)
            if NEGATED_GUEST_USER_PREDICATE.search(decoded_query):
                continue
            if GUEST_USER_PREDICATE.search(decoded_query):
                return True
        return False

    def _is_recurring_with_reviewers(self, definition) -> bool:
        """Determine whether recurrence and primary reviewers are configured."""
        return (
            definition.recurrence_pattern_type in ALLOWED_RECURRENCE_PATTERNS
            and definition.recurrence_range_type == "noEnd"
            and definition.has_primary_reviewers
        )

    def _is_fail_closed(self, definition) -> bool:
        """Determine whether an access review definition is fail-closed.

        Args:
            definition: The access review definition to evaluate.

        Returns:
            bool: True if the review enables and denies access by default,
            auto-applies decisions, and has mail notifications and reminders enabled.
        """
        return (
            definition.default_decision == "Deny"
            and definition.default_decision_enabled
            and definition.auto_apply_enabled
            and definition.mail_notifications_enabled
            and definition.reminders_enabled
        )

    def execute(self) -> List[CheckReportM365]:
        """Evaluate whether a compliant access review for guest users exists.

        Searches the tenant's access review definitions for an active, recurring,
        reviewer-assigned, fail-closed review scoped to guest users.

        Returns:
            List[CheckReportM365]: A single report indicating whether a compliant
            access review scoped to guest users is configured.
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
            "No compliant recurring access review scoped to guest users is configured "
            "with assigned primary reviewers."
        )

        for definition in definitions:
            if (
                definition.status in ACTIVE_STATUSES
                and self._targets_guest_users(definition)
                and self._is_fail_closed(definition)
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
                    "guest users is active, recurring, reviewer-assigned, and "
                    "fail-closed."
                )
                break

        findings.append(report)
        return findings
