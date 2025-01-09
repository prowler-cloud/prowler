from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.efs.efs_client import efs_client


class efs_multi_az_enabled(Check):
    def execute(self):
        findings = []
        for fs in efs_client.filesystems.values():
            report = Check_Report_AWS(self.metadata())
            report.region = fs.region
            report.resource_id = fs.id
            report.resource_arn = fs.arn
            report.resource_tags = fs.tags
            if fs.availability_zone_id:
                report.status = "FAIL"
                report.status_extended = f"EFS {fs.id} is a Single-AZ file system."
            else:
                if fs.number_of_mount_targets <= 1:
                    report.status = "FAIL"
                    report.status_extended = f"EFS {fs.id} is a Multi-AZ file system but with only one mount target."
                else:
                    report.status = "PASS"
                    report.status_extended = f"EFS {fs.id} is a Multi-AZ file system with more than one mount target."

            findings.append(report)

        return findings
