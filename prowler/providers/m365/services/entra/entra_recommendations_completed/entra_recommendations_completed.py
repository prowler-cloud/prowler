"""Check for Entra directory recommendations in a completed state."""

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    RecommendationStatus,
)


class entra_recommendations_completed(Check):
    """Ensure Entra directory recommendations are completed.

    This check evaluates each Microsoft Entra directory recommendation to verify
    that it has been addressed by the system or by an administrator.

    - PASS: The recommendation status is completedBySystem or completedByUser.
    - FAIL: The recommendation is still active or postponed.

    Dismissed recommendations are reported with an informational severity.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the Entra recommendations check.

        Iterates over all directory recommendations retrieved from the Entra
        client and generates a report for each one indicating whether it has
        been completed.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for recommendation in entra_client.recommendations.values():
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=recommendation,
                resource_name=recommendation.display_name,
                resource_id=recommendation.id,
            )

            if recommendation.status in (
                RecommendationStatus.COMPLETED_BY_SYSTEM,
                RecommendationStatus.COMPLETED_BY_USER,
            ):
                report.status = "PASS"
                report.status_extended = f"Entra recommendation '{recommendation.display_name}' is completed."
            elif recommendation.status == RecommendationStatus.DISMISSED:
                report.status = "PASS"
                report.check_metadata.Severity = "informational"
                report.status_extended = f"Entra recommendation '{recommendation.display_name}' has been dismissed."
            else:
                report.status = "FAIL"
                num_impacted = len(recommendation.impacted_resources)
                report.status_extended = (
                    f"Entra recommendation '{recommendation.display_name}' is not completed"
                    f" with {num_impacted} impacted resource{'s' if num_impacted != 1 else ''}."
                )

            findings.append(report)

        return findings
