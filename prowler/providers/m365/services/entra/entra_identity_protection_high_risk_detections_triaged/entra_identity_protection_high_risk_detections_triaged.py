from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_identity_protection_high_risk_detections_triaged(Check):
    """Ensure all high-risk Identity Protection detections have been triaged.

    This check queries Microsoft Entra ID Protection for risk detections with
    ``riskLevel`` of ``high`` that remain in ``riskState`` ``atRisk``, meaning
    they have not been remediated, dismissed or confirmed.

    - PASS: No untriaged high-risk detections exist in the tenant.
    - FAIL: One or more high-risk detections remain untriaged.
    - MANUAL: Risk detections could not be read (missing Entra ID P2 license
      or IdentityRiskEvent.Read.All permission).
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the high-risk detections triage check.

        Returns:
            A list containing a single finding for the tenant.
        """
        findings = []

        if entra_client.high_risk_detections_error:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Identity Protection Risk Detections",
                resource_id=entra_client.tenant_domain,
            )
            report.status = "MANUAL"
            report.status_extended = (
                f"Cannot evaluate high-risk Identity Protection detections: "
                f"{entra_client.high_risk_detections_error}"
            )
            findings.append(report)
            return findings

        detections = entra_client.high_risk_detections or []

        report = CheckReportM365(
            metadata=self.metadata(),
            resource={},
            resource_name="Identity Protection Risk Detections",
            resource_id=entra_client.tenant_domain,
        )

        if not detections:
            report.status = "PASS"
            report.status_extended = (
                "No high-risk Identity Protection detections are pending triage."
            )
        else:
            count = len(detections)
            affected_users = sorted(
                {d.user_principal_name for d in detections if d.user_principal_name}
            )
            max_display = 5
            if len(affected_users) <= max_display:
                users_text = ", ".join(affected_users)
            else:
                users_text = (
                    ", ".join(affected_users[:max_display])
                    + f" and {len(affected_users) - max_display} more"
                )

            report.status = "FAIL"
            report.status_extended = (
                f"There are {count} high-risk Identity Protection detection(s) "
                f"still at risk affecting user(s): {users_text}."
            )

        findings.append(report)
        return findings
