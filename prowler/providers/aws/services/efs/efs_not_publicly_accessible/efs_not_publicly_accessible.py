from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.efs.efs_client import efs_client
from prowler.providers.aws.services.efs.lib.lib import is_public_access_allowed


class efs_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for fs in efs_client.filesystems:
            report = Check_Report_AWS(self.metadata())
            report.region = fs.region
            report.resource_id = fs.id
            report.resource_arn = fs.arn
            report.resource_tags = fs.tags
            report.status = "PASS"
            report.status_extended = f"EFS {fs.id} has a policy which does not allow access to any client within the VPC."
            if not fs.policy:
                report.status = "FAIL"
                report.status_extended = f"EFS {fs.id} doesn't have any policy which means it grants full access to any client within the VPC."
            else:
                for statement in fs.policy.get("Statement", []):
                    if statement.get("Effect") == "Allow" and is_public_access_allowed(
                        statement
                    ):
                        report.status = "FAIL"
                        report.status_extended = f"EFS {fs.id} has a policy which allows access to any client within the VPC."
                        break
            findings.append(report)
        return findings
