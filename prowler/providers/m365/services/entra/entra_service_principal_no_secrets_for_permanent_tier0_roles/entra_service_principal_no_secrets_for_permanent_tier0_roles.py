"""Check for service principals using client secrets with permanent Tier 0 role assignments."""

from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import TIER_0_ROLE_TEMPLATE_IDS


class entra_service_principal_no_secrets_for_permanent_tier0_roles(Check):
    """
    Service principal with permanent Control Plane role does not use client secrets.

    This check evaluates whether service principals that hold permanent assignments
    to Tier 0 (Control Plane) directory roles authenticate using client secrets
    instead of more secure alternatives such as certificates or managed identities.

    - PASS: The service principal does not use client secrets or does not hold a
      permanent Tier 0 directory role assignment.
    - FAIL: The service principal uses client secrets and has a permanent assignment
      to at least one Tier 0 directory role.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the service principal secret management check.

        Iterates over service principals and identifies those that combine password
        credentials (client secrets) with permanent Tier 0 directory role assignments.

        Returns:
            A list of reports containing the result of the check for each service principal.
        """
        findings = []

        for sp in entra_client.service_principals.values():
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=sp,
                resource_name=sp.name,
                resource_id=sp.id,
            )

            has_secrets = len(sp.password_credentials) > 0
            tier0_roles = [
                role_id
                for role_id in sp.directory_role_template_ids
                if role_id in TIER_0_ROLE_TEMPLATE_IDS
            ]

            if has_secrets and tier0_roles:
                report.status = "FAIL"
                report.status_extended = (
                    f"Service principal '{sp.name}' uses client secrets and has "
                    f"permanent assignment to {len(tier0_roles)} Control Plane "
                    f"(Tier 0) directory role(s)."
                )
            else:
                report.status = "PASS"
                if not has_secrets and not tier0_roles:
                    report.status_extended = (
                        f"Service principal '{sp.name}' does not use client secrets "
                        f"and has no Tier 0 directory role assignments."
                    )
                elif not has_secrets:
                    report.status_extended = (
                        f"Service principal '{sp.name}' does not use client secrets."
                    )
                else:
                    report.status_extended = (
                        f"Service principal '{sp.name}' has no permanent Tier 0 "
                        f"directory role assignments."
                    )

            findings.append(report)

        return findings
