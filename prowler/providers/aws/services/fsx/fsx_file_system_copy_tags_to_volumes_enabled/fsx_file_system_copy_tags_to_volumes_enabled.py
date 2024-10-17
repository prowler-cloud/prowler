from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.fsx.fsx_client import fsx_client


class fsx_file_system_copy_tags_to_volumes_enabled(Check):
    def execute(self):
        findings = []
        for file_system in fsx_client.file_systems.values():
            if file_system.copy_tags_to_volumes is not None:
                report = Check_Report_AWS(self.metadata())
                report.region = file_system.region
                report.resource_id = file_system.id
                report.resource_arn = file_system.arn
                report.resource_tags = file_system.tags
                report.status = "PASS"
                report.status_extended = f"FSx file system {file_system.id} has copy tags to volumes enabled."

                if not file_system.copy_tags_to_volumes:
                    report.status = "FAIL"
                    report.status_extended = f"FSx file system {file_system.id} does not have copy tags to volumes enabled."

                findings.append(report)

        return findings
