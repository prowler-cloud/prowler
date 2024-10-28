from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.efs.efs_client import efs_client
from prowler.providers.aws.services.iam.lib.policy import is_policy_public


class efs_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for fs in efs_client.filesystems.values():
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
            elif is_policy_public(fs.policy, efs_client.audited_account) and any(
                statement.get("Condition", {})
                .get("Bool", {})
                .get("elasticfilesystem:AccessedViaMountTarget", "false")
                != "true"
                for statement in fs.policy.get("Statement", [])
            ):
                report.status = "FAIL"
                report.status_extended = f"EFS {fs.id} has a policy which allows access to any client within the VPC."
            findings.append(report)
        return findings
