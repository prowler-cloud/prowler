from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.efs.efs_client import efs_client


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
            report.status_extended = (
                f"EFS {fs.id} has a policy which does not allow access to everyone."
            )
            if not fs.policy:
                report.status = "FAIL"
                report.status_extended = f"EFS {fs.id} doesn't have any policy which means it grants full access to any client."
            else:
                for statement in fs.policy.get("Statement", []):
                    if statement.get(
                        "Effect"
                    ) == "Allow" and self.is_public_access_allowed(statement):
                        report.status = "FAIL"
                        report.status_extended = (
                            f"EFS {fs.id} has a policy which allows access to everyone."
                        )
                        break
            findings.append(report)
        return findings

    def is_public_access_allowed(self, statement):
        principal = statement.get("Principal")
        if principal == "*" or (
            isinstance(principal, dict) and "*" in principal.values()
        ):
            return not self.has_secure_conditions(statement)
        return False

    def has_secure_conditions(self, statement):
        conditions = statement.get("Condition", {})
        allowed_conditions = {
            "aws:SourceArn",
            "aws:SourceVpc",
            "aws:SourceVpce",
            "aws:SourceOwner",
            "aws:SourceAccount",
        }
        if (
            "Bool" in conditions
            and conditions["Bool"].get("elasticfilesystem:AccessedViaMountTarget")
            == "true"
        ):
            return True

        # Check for conditions with nested keys
        for _, conditions_dict in conditions.items():
            for key, value in conditions_dict.items():
                if isinstance(value, dict):
                    if set(value.keys()).intersection(allowed_conditions):
                        return True
                elif key in allowed_conditions:
                    return True
        return False
