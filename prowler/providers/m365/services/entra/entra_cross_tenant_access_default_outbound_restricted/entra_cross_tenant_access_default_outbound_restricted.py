from typing import List, Optional, Set

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    CrossTenantB2BSetting,
    CrossTenantTargetConfiguration,
)

# Targets that cover every user or every application. AllMicrosoftApps is
# treated as broad too: allowing it opens and blocking it closes access to
# every Microsoft cloud application.
ALL_USERS_TARGETS = {"AllUsers"}
ALL_APPLICATIONS_TARGETS = {"AllApplications", "AllMicrosoftApps"}


class entra_cross_tenant_access_default_outbound_restricted(Check):
    """Ensure default cross-tenant access outbound settings are restricted.

    The default cross-tenant access policy must not allow every user and group
    to access every application of any external tenant through B2B collaboration
    outbound or B2B direct connect outbound.

    - PASS: Neither b2bCollaborationOutbound nor b2bDirectConnectOutbound is
      fully open (allowed for AllUsers AND AllApplications).
    - FAIL: At least one of the outbound settings allows all users and all
      applications.
    - MANUAL: The default policy or one of its outbound settings could not be
      read or is incomplete, and no setting is fully open.
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

        if policy is None:
            report.status = "MANUAL"
            report.status_extended = (
                "Cannot evaluate the default cross-tenant access outbound settings: "
                "the policy could not be read. "
                "Verify that the Policy.Read.All permission is granted to the scanning application."
            )
            findings.append(report)
            return findings

        collaboration_open = self._is_fully_open(policy.b2b_collaboration_outbound)
        direct_connect_open = self._is_fully_open(policy.b2b_direct_connect_outbound)

        unrestricted_settings = []
        if collaboration_open:
            unrestricted_settings.append("B2B collaboration outbound")
        if direct_connect_open:
            unrestricted_settings.append("B2B direct connect outbound")

        if unrestricted_settings:
            report.status = "FAIL"
            joined = " and ".join(unrestricted_settings)
            report.status_extended = (
                f"Default cross-tenant access policy leaves {joined} broadly open: "
                f"access is not limited to specific users or groups and to specific "
                f"applications in external tenants."
            )
        elif collaboration_open is None or direct_connect_open is None:
            report.status = "MANUAL"
            report.status_extended = (
                "Cannot evaluate the default cross-tenant access outbound settings: "
                "the users and groups or applications configuration of an outbound "
                "setting is incomplete."
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
    def _is_fully_open(setting: Optional[CrossTenantB2BSetting]) -> Optional[bool]:
        """Determine whether a B2B outbound setting is broadly open.

        In the default policy a ``blocked`` list is an exception list: blocking
        specific users, groups or applications leaves everything else allowed.
        A dimension is therefore restricted only when it is ``allowed`` for
        specific targets or ``blocked`` for everyone. The setting is open when
        neither users and groups nor applications are restricted.

        Args:
            setting: The B2B setting to evaluate, or None if absent.

        Returns:
            True if the setting is broadly open, False if users or applications
            are restricted, or None if its configuration is missing or incomplete.
        """
        if setting is None:
            return None

        configurations = (setting.users_and_groups, setting.applications)
        if any(
            config is None
            or config.access_type not in ("allowed", "blocked")
            or not config.targets
            for config in configurations
        ):
            return None

        users_open = (
            entra_cross_tenant_access_default_outbound_restricted._dimension_open(
                setting.users_and_groups,
                allowed_all_targets=ALL_USERS_TARGETS,
                blocked_all_targets=ALL_USERS_TARGETS,
            )
        )
        apps_open = (
            entra_cross_tenant_access_default_outbound_restricted._dimension_open(
                setting.applications,
                allowed_all_targets=ALL_APPLICATIONS_TARGETS,
                blocked_all_targets=ALL_APPLICATIONS_TARGETS,
            )
        )
        return users_open and apps_open

    @staticmethod
    def _dimension_open(
        config: CrossTenantTargetConfiguration,
        allowed_all_targets: Set[str],
        blocked_all_targets: Set[str],
    ) -> bool:
        """Tell whether one dimension (users or applications) is left open.

        Args:
            config: The users-and-groups or applications configuration.
            allowed_all_targets: Targets that open the dimension when allowed.
            blocked_all_targets: Targets that close the dimension when blocked.

        Returns:
            True if everyone (or every application) can still be reached.
        """
        targets = {target.target for target in config.targets}
        if config.access_type == "allowed":
            return bool(targets & allowed_all_targets)
        # blocked: only blocking everyone restricts the dimension.
        return not targets & blocked_all_targets
