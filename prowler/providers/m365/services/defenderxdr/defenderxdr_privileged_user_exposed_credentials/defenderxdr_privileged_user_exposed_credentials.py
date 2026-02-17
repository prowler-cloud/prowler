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

    Prerequisites:
    1. ThreatHunting.Read.All permission granted
    2. Security Exposure Management enabled with data from at least one
       Microsoft Defender service (Defender for Endpoint, Defender for Identity,
       Defender for Cloud, Entra ID, or third-party connectors)

    Results:
    - PASS: No exposed credentials found for privileged users
    - FAIL: Exposed credentials detected OR unable to query Exposure Management
    """

    def execute(self) -> list[CheckReportM365]:
        """
        Execute the check for exposed credentials of privileged users.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []

        exposed_credentials = defenderxdr_client.exposed_credentials_privileged_users

        # None means API call failed - could be permissions or Exposure Management not enabled
        if exposed_credentials is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender XDR Exposure Management",
                resource_id="exposureGraphEdges",
            )
            report.status = "FAIL"
            report.status_extended = (
                "Unable to query Security Exposure Management data. "
                "Verify ThreatHunting.Read.All permission is granted and "
                "at least one Microsoft Defender service is deployed in the tenant."
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
            # Empty list - query worked but no exposed credentials found
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Defender XDR Exposure Management",
                resource_id="exposureGraphEdges",
            )
            report.status = "PASS"
            report.status_extended = "No exposed credentials found for privileged users on vulnerable endpoints."
            findings.append(report)

        return findings
