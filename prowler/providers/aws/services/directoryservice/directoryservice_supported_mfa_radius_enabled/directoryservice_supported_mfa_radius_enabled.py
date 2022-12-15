from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.directoryservice.directoryservice_client import (
    directoryservice_client,
)
from prowler.providers.aws.services.directoryservice.directoryservice_service import (
    RadiusStatus,
)


class directoryservice_supported_mfa_radius_enabled(Check):
    def execute(self):
        findings = []
        for directory in directoryservice_client.directories.values():
            if directory.radius_settings:
                report = Check_Report_AWS(self.metadata())
                report.region = directory.region
                report.resource_id = directory.id
                if directory.radius_settings.status == RadiusStatus.Completed:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Directory {directory.id} have Radius MFA enabled"
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Directory {directory.id} does not have Radius MFA enabled"
                    )

                findings.append(report)

        return findings
