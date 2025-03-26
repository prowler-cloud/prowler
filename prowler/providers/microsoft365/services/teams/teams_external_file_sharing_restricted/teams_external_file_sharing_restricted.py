from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.teams.teams_client import teams_client


class teams_external_file_sharing_restricted(Check):
    """Check if external file sharing is restricted in Teams.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """Execute the check for external file sharing settings in Teams.

        This method checks if external file sharing is restricted in Teams. If external file sharing
        is restricted to only approved cloud storage services the check passes; otherwise, it fails.

        Returns:
            List[CheckReportMicrosoft365]: A list of reports containing the result of the check.
        """
        findings = []

        report = CheckReportMicrosoft365(
            metadata=self.metadata(),
            resource=teams_client.teams_settings.cloud_storage_settings,
            resource_name="Cloud Storage Settings",
            resource_id="cloudStorageSettings",
        )
        report.status = "FAIL"
        report.status_extended = "External file sharing is not restricted to only approved cloud storage services."

        if all(
            report.resource.get(key, True) is False
            for key in [
                "allow_box",
                "allow_drop_box",
                "allow_egnyte",
                "allow_google_drive",
                "allow_share_file",
            ]
        ):
            report.status = "PASS"
            report.status_extended = "External file sharing is restricted to only approved cloud storage services."

        findings.append(report)

        return findings
