"""
Check for exposed credentials of privileged users in Microsoft Defender for Endpoint.

This check identifies privileged users whose authentication credentials
(CLI secrets, cookies, tokens) are exposed on vulnerable endpoints.
"""

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defenderendpoint.defenderendpoint_client import (
    defenderendpoint_client,
)


class defenderendpoint_privileged_user_exposed_credentials(Check):
    """
    Check if privileged users have exposed credentials on vulnerable endpoints.

    This check queries Microsoft Defender for Endpoint's ExposureGraphEdges table
    via the Advanced Hunting API to identify privileged users whose authentication
    artifacts (CLI secrets, user cookies, sensitive tokens) are exposed on endpoints
    with high risk or exposure scores.

    Prerequisites:
    1. ThreatHunting.Read.All permission granted
    2. Microsoft Defender for Endpoint (MDE) enabled and deployed on devices

    Results:
    - PASS: No exposed credentials found OR MDE enabled but no devices to evaluate
    - FAIL: Exposed credentials detected OR MDE not enabled (security blind spot)
    """

    def execute(self) -> list[CheckReportM365]:
        """
        Execute the check for exposed credentials of privileged users.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []

        # Step 1: Check MDE status
        mde_status = defenderendpoint_client.mde_status

        # API call failed - likely missing ThreatHunting.Read.All permission
        if mde_status is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender for Endpoint",
                resource_id="mdeStatus",
            )
            report.status = "FAIL"
            report.status_extended = (
                "Unable to query Microsoft Defender for Endpoint status. "
                "Verify that ThreatHunting.Read.All permission is granted."
            )
            findings.append(report)
            return findings

        # MDE not enabled - this is a security blind spot
        if mde_status == "not_enabled":
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender for Endpoint",
                resource_id="mdeStatus",
            )
            report.status = "FAIL"
            report.status_extended = (
                "Microsoft Defender for Endpoint is not enabled. "
                "Without MDE there is no visibility into credential exposure on endpoints."
            )
            findings.append(report)
            return findings

        # MDE enabled but no devices - PASS because there are no endpoints to evaluate
        if mde_status == "no_devices":
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender for Endpoint",
                resource_id="mdeDevices",
            )
            report.status = "PASS"
            report.status_extended = (
                "Microsoft Defender for Endpoint is enabled but no devices are onboarded. "
                "No endpoints to evaluate for credential exposure."
            )
            findings.append(report)
            return findings

        # Step 2: MDE is active with devices - check for exposed credentials
        exposed_credentials = (
            defenderendpoint_client.exposed_credentials_privileged_users
        )

        # API call failed for exposed credentials query
        if exposed_credentials is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender for Endpoint",
                resource_id="exposedCredentials",
            )
            report.status = "FAIL"
            report.status_extended = (
                "Unable to query Security Exposure Management for exposed credentials. "
                "Verify that Security Exposure Management is enabled."
            )
            findings.append(report)
            return findings

        # Found exposed credentials - report each one
        if exposed_credentials:
            for exposed_user in exposed_credentials:
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=exposed_user,
                    resource_name=exposed_user.target_node_name,
                    resource_id=exposed_user.target_node_id or exposed_user.edge_id,
                )
                report.status = "FAIL"

                credential_info = (
                    f" ({exposed_user.credential_type})"
                    if exposed_user.credential_type
                    else ""
                )
                report.status_extended = (
                    f"Privileged user {exposed_user.target_node_name} has exposed "
                    f"credentials{credential_info} on device {exposed_user.source_node_name}."
                )
                findings.append(report)
        else:
            # No exposed credentials found - full visibility, no risk detected
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender for Endpoint Exposure Management",
                resource_id="exposedCredentials",
            )
            report.status = "PASS"
            report.status_extended = "No exposed credentials found for privileged users on vulnerable endpoints."
            findings.append(report)

        return findings
