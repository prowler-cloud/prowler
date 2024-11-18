from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.fsx.fsx_client import fsx_client


class fsx_windows_file_system_multi_az_enabled(Check):
    def execute(self):
        findings = []
        for file_system in fsx_client.file_systems.values():
            if file_system.type == "WINDOWS":
                report = Check_Report_AWS(self.metadata())
                report.region = file_system.region
                report.resource_id = file_system.id
                report.resource_arn = file_system.arn
                report.resource_tags = file_system.tags
                if len(file_system.subnet_ids) > 1:
                    report.status = "PASS"
                    report.status_extended = f"FSx Windows file system {file_system.id} is configured for Multi-AZ deployment."

                else:
                    report.status = "FAIL"
                    report.status_extended = f"FSx Windows file system {file_system.id} is not configured for Multi-AZ deployment."

                findings.append(report)

        return findings
