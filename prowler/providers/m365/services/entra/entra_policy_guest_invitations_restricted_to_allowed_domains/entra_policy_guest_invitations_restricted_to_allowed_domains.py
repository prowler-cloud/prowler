from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_policy_guest_invitations_restricted_to_allowed_domains(Check):
    """Check if guest invitations are restricted to an allow-list of domains.

    The B2B collaboration policy should allow invitations only to a specified list of
    domains (most restrictive), with at least one allowed domain configured.

    - PASS: Invitations are restricted to an allow-list with at least one domain.
    - FAIL: Invitations are not restricted to an allow-list of domains.
    """

    def execute(self) -> List[CheckReportM365]:
        """Evaluate whether guest invitations are restricted to allowed domains.

        Inspects the B2B collaboration policy to determine whether guest invitations
        are limited to an allow-list of domains that contains at least one domain.

        Returns:
            List[CheckReportM365]: A single report indicating whether guest
            invitations are restricted to a non-empty allow-list of domains, or an
            empty list when the policy is absent.
        """
        findings = []
        policy = entra_client.b2b_collaboration_policy
        if not policy:
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=policy,
            resource_name="B2B Collaboration Policy",
            resource_id="b2bManagementPolicy",
        )
        report.status = "FAIL"
        report.status_extended = (
            "Guest invitations are not restricted to an allow-list of domains."
        )

        if policy.invitations_restricted_to_allowed_domains and policy.allowed_domains:
            report.status = "PASS"
            report.status_extended = (
                "Guest invitations are restricted to an allow-list of "
                f"{len(policy.allowed_domains)} domain(s)."
            )

        findings.append(report)
        return findings
