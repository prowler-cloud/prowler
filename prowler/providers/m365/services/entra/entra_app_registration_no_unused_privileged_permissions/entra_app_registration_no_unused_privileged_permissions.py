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
      It also fails when OAuth App Governance data is not available.
    """

    # InUse field values from OAuthAppInfo:
    # - "true" / "1" / "True" = permission is actively used
    # - "false" / "0" / "False" = permission is NOT used (this triggers FAIL)
    # - "Not supported" = Microsoft cannot determine usage
    # - "" (empty) = No tracking data available
    # Note: Microsoft is changing from numeric (1/0) to textual (True/False) on Feb 25, 2026
    _UNUSED_STATUSES = {"false", "0", "notinuse", "not in use"}
    _PRIVILEGED_PLANE_LABELS = ("control plane", "management plane")

    def execute(self) -> list[CheckReportM365]:
        """
        Execute the unused privileged permissions check for app registrations.

        Iterates over OAuth applications retrieved from the Entra client and generates
        reports indicating whether each app has unused privileged permissions.

        Returns:
            list[CheckReportM365]: A list of reports with the result of the check for each app.
        """
        findings = []

        # If OAuth app data is None, the API call failed (missing permissions or App Governance not enabled)
        if entra_client.oauth_apps is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="OAuth Applications",
                resource_id="oauthApps",
            )
            report.status = "FAIL"
            report.status_extended = (
                "OAuth App Governance data is unavailable. "
                "Enable App Governance in Microsoft Defender for Cloud Apps and "
                "grant ThreatHunting.Read.All to evaluate unused privileged permissions."
            )
            findings.append(report)
            return findings

        # If OAuth apps is empty dict, no apps are registered - this is compliant
        if not entra_client.oauth_apps:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="OAuth Applications",
                resource_id="oauthApps",
            )
            report.status = "PASS"
            report.status_extended = (
                "No OAuth applications are registered in the tenant."
            )
            findings.append(report)
            return findings

        # Check each OAuth app for unused privileged permissions
        for app_id, app in entra_client.oauth_apps.items():
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=app,
                resource_name=app.name,
                resource_id=app_id,
            )

            # Find unused privileged permissions
            # A permission is considered privileged if it has:
            # - PrivilegeLevel == "High"
            # Or if it's part of Control Plane / Management Plane (typically High privilege)
            unused_privileged_permissions = []

            for permission in app.permissions:
                # Check if the permission is privileged
                is_privileged = self._is_privileged_permission(permission)

                # Check if the permission is unused
                normalized_usage = self._normalize(permission.usage_status)
                is_unused = normalized_usage in self._UNUSED_STATUSES

                if is_privileged and is_unused:
                    unused_privileged_permissions.append(permission.name)

            if unused_privileged_permissions:
                # The app has unused privileged permissions
                report.status = "FAIL"
                # Truncate list to first 5 permissions for readability
                total_count = len(unused_privileged_permissions)
                if total_count > 5:
                    displayed = unused_privileged_permissions[:5]
                    permissions_list = ", ".join(displayed)
                    remaining = total_count - 5
                    permissions_list += f" (and {remaining} more)"
                else:
                    permissions_list = ", ".join(unused_privileged_permissions)
                report.status_extended = (
                    f"App registration {app.name} has {total_count} "
                    f"unused privileged permission(s): {permissions_list}."
                )
            else:
                # The app has no unused privileged permissions
                report.status = "PASS"
                report.status_extended = (
                    f"App registration {app.name} has no unused privileged permissions."
                )

            findings.append(report)

        return findings

    @classmethod
    def _is_privileged_permission(cls, permission) -> bool:
        privilege_level = cls._normalize(permission.privilege_level)
        permission_type = cls._normalize(permission.permission_type)
        classification = cls._normalize(getattr(permission, "classification", ""))

        if privilege_level == "high":
            return True

        return any(
            label in permission_type or label in classification
            for label in cls._PRIVILEGED_PLANE_LABELS
        )

    @staticmethod
    def _normalize(value: str) -> str:
        return (
            value.lower().replace("_", " ").replace("-", " ").strip() if value else ""
        )
