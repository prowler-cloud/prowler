"""Check that Self-Service Password Reset is disabled for administrators."""

from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_policy_admin_self_service_password_reset_disabled(Check):
    """Ensure that Self-Service Password Reset (SSPR) is disabled for administrators.

    This check evaluates the tenant authorization policy to verify that the
    ``allowedToUseSSPR`` property is set to ``false``, preventing administrators
    from resetting their own passwords through SSPR.

    - PASS: ``allowedToUseSSPR`` is ``false`` (administrators cannot use SSPR).
    - FAIL: ``allowedToUseSSPR`` is ``true`` (SSPR is enabled for administrators).
    - MANUAL: The authorization policy or the property could not be read.
    """

    def execute(self) -> List[CheckReportM365]:
        """Evaluate allowedToUseSSPR on the tenant authorization policy."""
        findings = []
        auth_policy = entra_client.authorization_policy

        if auth_policy is None or auth_policy.allowed_to_use_sspr is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=auth_policy if auth_policy else {},
                resource_name="Authorization Policy",
                resource_id="authorizationPolicy",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Cannot evaluate whether SSPR is disabled for administrators: the "
                "authorization policy or its allowedToUseSSPR setting could not be "
                "retrieved. Check the scanning application's permissions and any "
                "Microsoft Graph API errors in the scan log."
            )
            findings.append(report)
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=auth_policy,
            resource_name=auth_policy.name,
            resource_id=auth_policy.id,
        )

        if not auth_policy.allowed_to_use_sspr:
            report.status = "PASS"
            report.status_extended = (
                "Self-Service Password Reset (SSPR) is disabled for administrators "
                "(allowedToUseSSPR is false in the authorization policy)."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                "Self-Service Password Reset (SSPR) is enabled for administrators "
                "(allowedToUseSSPR is true in the authorization policy)."
            )

        findings.append(report)
        return findings
