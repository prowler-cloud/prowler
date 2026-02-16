from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_app_registration_no_unused_privileged_permissions(Check):
    """
    Ensure that app registrations do not have unused privileged API permissions.

    This check evaluates OAuth applications registered in Microsoft Entra ID to identify
    those with privileged API permissions (High privilege level or Control/Management Plane
    classifications) that are assigned but not actively being used.

    The check uses data from Microsoft Defender for Cloud Apps App Governance via
    the OAuthAppInfo table in Defender XDR Advanced Hunting.

    - PASS: The app has no unused privileged permissions.
    - FAIL: The app has one or more unused privileged permissions that should be revoked.
    """

    def execute(self) -> list[CheckReportM365]:
        """
        Execute the unused privileged permissions check for app registrations.

        Iterates over OAuth applications retrieved from the Entra client and generates
        reports indicating whether each app has unused privileged permissions.

        Returns:
            list[CheckReportM365]: A list of reports with the result of the check for each app.
        """
        findings = []

        # Check if OAuth app data is available
        if not entra_client.oauth_apps:
            # If no data is available, create a single informational finding
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="OAuth Applications",
                resource_id="oauthApps",
            )
            report.status = "PASS"
            report.status_extended = (
                "No OAuth applications found or App Governance is not enabled. "
                "Enable App Governance in Microsoft Defender for Cloud Apps to "
                "monitor OAuth app permissions."
            )
            findings.append(report)
            return findings

        # Check each OAuth app for unused privileged permissions
        for app_id, app in entra_client.oauth_apps.items():
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=app,
                resource_name=app.name if app.name else app_id,
                resource_id=app_id,
            )

            # Find unused privileged permissions
            # A permission is considered privileged if it has:
            # - PrivilegeLevel == "High"
            # Or if it's part of Control Plane / Management Plane (typically High privilege)
            unused_privileged_permissions = []

            for permission in app.permissions:
                # Check if the permission is privileged
                is_privileged = permission.privilege_level.lower() == "high"

                # Check if the permission is unused
                is_unused = permission.usage_status.lower() in [
                    "notinuse",
                    "not_in_use",
                ]

                if is_privileged and is_unused:
                    unused_privileged_permissions.append(permission.name)

            if unused_privileged_permissions:
                # The app has unused privileged permissions
                report.status = "FAIL"
                permissions_list = ", ".join(unused_privileged_permissions[:5])
                if len(unused_privileged_permissions) > 5:
                    permissions_list += (
                        f" (and {len(unused_privileged_permissions) - 5} more)"
                    )
                report.status_extended = (
                    f"App registration '{app.name}' has {len(unused_privileged_permissions)} "
                    f"unused privileged permission(s): {permissions_list}."
                )
            else:
                # The app has no unused privileged permissions
                report.status = "PASS"
                report.status_extended = f"App registration '{app.name}' has no unused privileged permissions."

            findings.append(report)

        return findings
