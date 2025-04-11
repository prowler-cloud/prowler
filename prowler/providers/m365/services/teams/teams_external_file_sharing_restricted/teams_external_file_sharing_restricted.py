from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.teams.teams_client import teams_client
from prowler.providers.m365.services.teams.teams_service import CloudStorageSettings


class teams_external_file_sharing_restricted(Check):
    """Check if external file sharing is restricted in Teams.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for external file sharing settings in Teams.

        This method checks if external file sharing is restricted in Teams. If external file sharing
        is restricted to only approved cloud storage services the check passes; otherwise, it fails.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        cloud_storage_settings = teams_client.teams_settings.cloud_storage_settings
        report = CheckReportM365(
            metadata=self.metadata(),
            resource=cloud_storage_settings if cloud_storage_settings else {},
            resource_name="Cloud Storage Settings",
            resource_id="cloudStorageSettings",
        )
        report.status = "FAIL"
        report.status_extended = "External file sharing is not restricted to only approved cloud storage services."

        allowed_services = teams_client.audit_config.get(
            "allowed_cloud_storage_services", []
        )
        if cloud_storage_settings:
            # Get storage services from CloudStorageSettings class items
            storage_services = [
                attr
                for attr, type_hint in CloudStorageSettings.__annotations__.items()
                if type_hint is bool
            ]

            # Check if all services are disabled when no allowed services are specified
            # or if all enabled services are in the allowed list
            if (
                not allowed_services
                and all(
                    not getattr(cloud_storage_settings, service, True)
                    for service in storage_services
                )
            ) or (
                allowed_services
                and not any(
                    getattr(cloud_storage_settings, service, True)
                    and service not in allowed_services
                    for service in storage_services
                )
            ):
                report.status = "PASS"
                report.status_extended = "External file sharing is restricted to only approved cloud storage services."

        findings.append(report)

        return findings
