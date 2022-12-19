from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.efs.efs_client import efs_client


class efs_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for fs in efs_client.filesystems:
            report = Check_Report_AWS(self.metadata())
            report.region = fs.region
            report.resource_id = fs.id
            report.resource_arn = ""
            report.status = "PASS"
            report.status_extended = (
                f"EFS {fs.id} has policy which does not allow access to everyone"
            )
            if not fs.policy:
                report.status = "FAIL"
                report.status_extended = f"EFS {fs.id} doesn't have any policy which means it grants full access to any client"
            else:
                for statement in fs.policy["Statement"]:
                    if statement["Effect"] == "Allow":
                        if (
                            statement["Principal"]["AWS"] == "*"
                            or statement["Principal"] == "*"
                            or (
                                "CanonicalUser" in statement["Principal"]
                                and statement["Principal"]["CanonicalUser"] == "*"
                            )
                        ):
                            report.status = "FAIL"
                            report.status_extended = f"EFS {fs.id} has policy which allows access to everyone"
                            break
            findings.append(report)

        return findings
