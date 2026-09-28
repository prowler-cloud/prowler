from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_policy_guest_invitations_restricted_to_allowed_domains(Check):
    """Check if guest invitations are restricted by an allowed-domain policy.

    The B2B collaboration policy should allow invitations only to a specified list of
    domains (most restrictive). An empty allow-list blocks invitations from every
    external domain and is compliant.

    - PASS: Invitations are restricted to an allow-list, including an empty block-all
      list.
    - FAIL: Invitations are not restricted to an allow-list of domains.
    """

    def execute(self) -> List[CheckReportM365]:
        """Evaluate whether guest invitations are restricted to allowed domains.

        Inspects the B2B collaboration policy to determine whether guest invitations
        are limited to an allow-list of domains. An empty allow-list blocks all external
        invitations.

        Returns:
            List[CheckReportM365]: A single report indicating whether guest
            invitations are restricted by an allowed-domain policy, or an empty list
            when the policy is absent.
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

        if policy.invitations_restricted_to_allowed_domains:
            report.status = "PASS"
            if policy.allowed_domains:
                report.status_extended = (
                    "Guest invitations are restricted to an allow-list of "
                    f"{len(policy.allowed_domains)} domain(s)."
                )
            else:
                report.status_extended = (
                    "Guest invitations are blocked for all external domains."
                )

        findings.append(report)
        return findings
