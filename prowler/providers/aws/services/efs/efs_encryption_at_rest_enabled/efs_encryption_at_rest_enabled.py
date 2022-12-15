from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.efs.efs_client import efs_client


class efs_encryption_at_rest_enabled(Check):
    def execute(self):
        findings = []
        for fs in efs_client.filesystems:
            report = Check_Report_AWS(self.metadata())
            report.region = fs.region
            report.resource_id = fs.id
            report.resource_arn = ""
            report.status = "FAIL"
            report.status_extended = (
                f"EFS {fs.id} does not have encryption at rest enabled"
            )
            if fs.encrypted:
                report.status = "PASS"
                report.status_extended = f"EFS {fs.id} has encryption at rest enabled"

            findings.append(report)

        return findings
