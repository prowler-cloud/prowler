from typing import List, Optional

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import CrossTenantB2BSetting


class entra_cross_tenant_access_default_outbound_restricted(Check):
    """Ensure default cross-tenant access outbound settings are restricted.

    The default cross-tenant access policy must not allow every user and group
    to access every application of any external tenant through B2B collaboration
    outbound or B2B direct connect outbound.

    - PASS: Neither b2bCollaborationOutbound nor b2bDirectConnectOutbound is
      fully open (allowed for AllUsers AND AllApplications).
    - FAIL: At least one of the outbound settings allows all users and all
      applications.
    - MANUAL: The default policy or one of its outbound settings could not be read.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the cross-tenant access default outbound restriction check.

        Evaluates the tenant's default cross-tenant access policy to determine
        whether B2B collaboration outbound and/or B2B direct connect outbound
        are unrestricted (allowed for all users and all applications).

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        policy = entra_client.cross_tenant_access_default

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=policy if policy else {},
            resource_name="Cross-Tenant Access Default Policy",
            resource_id="crossTenantAccessPolicyConfigurationDefault",
        )

        if (
            policy is None
            or policy.b2b_collaboration_outbound is None
            or policy.b2b_direct_connect_outbound is None
        ):
            report.status = "MANUAL"
            report.status_extended = (
                "Cannot evaluate the default cross-tenant access outbound settings: "
                "the policy or its outbound settings could not be read. "
                "Verify that the Policy.Read.All permission is granted to the scanning application."
            )
            findings.append(report)
            return findings

        unrestricted_settings = []

        if self._is_fully_open(policy.b2b_collaboration_outbound):
            unrestricted_settings.append("B2B collaboration outbound")

        if self._is_fully_open(policy.b2b_direct_connect_outbound):
            unrestricted_settings.append("B2B direct connect outbound")

        if unrestricted_settings:
            report.status = "FAIL"
            joined = " and ".join(unrestricted_settings)
            report.status_extended = (
                f"Default cross-tenant access policy has unrestricted outbound "
                f"access: {joined} allows all users to access all applications "
                f"in any external tenant."
            )
        else:
            report.status = "PASS"
            report.status_extended = (
                "Default cross-tenant access policy restricts outbound access "
                "for both B2B collaboration and B2B direct connect."
            )

        findings.append(report)
        return findings

    @staticmethod
    def _is_fully_open(setting: Optional[CrossTenantB2BSetting]) -> bool:
        """Determine whether a B2B outbound setting is fully open.

        A setting is fully open when usersAndGroups has accessType ``allowed``
        with a target of ``AllUsers`` AND applications has accessType ``allowed``
        with a target of ``AllApplications``.

        Args:
            setting: The B2B setting to evaluate, or None if absent.

        Returns:
            True if the setting is fully open, False otherwise.
        """
        if setting is None:
            return False

        users_open = False
        apps_open = False

        if (
            setting.users_and_groups is not None
            and setting.users_and_groups.access_type == "allowed"
        ):
            for target in setting.users_and_groups.targets:
                if target.target == "AllUsers":
                    users_open = True
                    break

        if (
            setting.applications is not None
            and setting.applications.access_type == "allowed"
        ):
            for target in setting.applications.targets:
                if target.target == "AllApplications":
                    apps_open = True
                    break

        return users_open and apps_open
