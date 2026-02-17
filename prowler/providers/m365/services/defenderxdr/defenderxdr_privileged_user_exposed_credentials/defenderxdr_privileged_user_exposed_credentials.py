"""
Check for exposed credentials of privileged users in Microsoft Defender XDR.

This check identifies privileged users whose authentication credentials
(CLI secrets, cookies, tokens) are exposed on vulnerable endpoints.
"""

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defenderxdr.defenderxdr_client import (
    defenderxdr_client,
)


class defenderxdr_privileged_user_exposed_credentials(Check):
    """
    Check if privileged users have exposed credentials on vulnerable endpoints.

    This check queries Microsoft Defender XDR's ExposureGraphEdges table to
    identify privileged users whose authentication artifacts (CLI secrets,
    user cookies, sensitive tokens) are exposed on endpoints with high risk
    or exposure scores.

    Prerequisites (checked in order):
    1. ThreatHunting.Read.All permission granted
    2. Microsoft Defender for Endpoint deployed on devices
    3. Security Exposure Management enabled

    Results:
    - PASS: No exposed credentials found (with full visibility)
    - FAIL: Exposed credentials detected OR prerequisites not met
    """

    def execute(self) -> list[CheckReportM365]:
        """
        Execute the check for exposed credentials of privileged users.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []

        # Step 1: Check MDE devices query result
        # If None -> API failed -> likely missing ThreatHunting.Read.All permission
        # If False -> Query worked but no devices -> MDE not deployed
        if defenderxdr_client.has_mde_devices is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender XDR",
                resource_id="mdeDevices",
            )
            report.status = "FAIL"
            report.status_extended = (
                "Cannot query Defender for Endpoint data. "
                "Grant ThreatHunting.Read.All permission to the application."
            )
            findings.append(report)
            return findings

        if defenderxdr_client.has_mde_devices is False:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender XDR",
                resource_id="mdeDevices",
            )
            report.status = "PASS"
            report.status_extended = (
                "No devices found in Microsoft Defender for Endpoint. "
                "No endpoints to evaluate for credential exposure."
            )
            findings.append(report)
            return findings

        # Step 2: Check Exposure Management query result
        # If we reach here, ThreatHunting.Read.All permission is working (step 1 passed)
        # If None -> API failed -> Exposure Management not enabled in tenant
        # If False -> Query worked but no data -> Exposure Management enabled but empty
        if defenderxdr_client.exposure_management_active is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender XDR",
                resource_id="exposureManagement",
            )
            report.status = "FAIL"
            report.status_extended = (
                "Cannot query Security Exposure Management data. "
                "Enable Security Exposure Management in Microsoft Defender XDR portal."
            )
            findings.append(report)
            return findings

        if defenderxdr_client.exposure_management_active is False:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender XDR",
                resource_id="exposureManagement",
            )
            report.status = "FAIL"
            report.status_extended = (
                "Security Exposure Management is enabled but has no exposure data. "
                "Wait for MDE to analyze device security posture and populate exposure graph."
            )
            findings.append(report)
            return findings

        # Step 3: Query exposed credentials
        # If we reach here, all prerequisites are met
        exposed_credentials = defenderxdr_client.exposed_credentials_privileged_users

        if exposed_credentials is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender XDR",
                resource_id="privilegedUserExposedCredentials",
            )
            report.status = "FAIL"
            report.status_extended = (
                "Failed to query exposed credentials. "
                "An unexpected error occurred while querying the ExposureGraphEdges table."
            )
            findings.append(report)
            return findings

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
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender XDR Exposure Management",
                resource_id="privilegedUserExposedCredentials",
            )
            report.status = "PASS"
            report.status_extended = "No exposed credentials found for privileged users on vulnerable endpoints."
            findings.append(report)

        return findings
