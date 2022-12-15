from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecr.ecr_client import ecr_client


class ecr_repositories_scan_images_on_push_enabled(Check):
    def execute(self):
        findings = []
        for repository in ecr_client.repositories:
            report = Check_Report_AWS(self.metadata())
            report.region = repository.region
            report.resource_id = repository.name
            report.resource_arn = repository.arn
            report.status = "PASS"
            report.status_extended = (
                f"ECR repository {repository.name} has scan on push enabled"
            )
            if not repository.scan_on_push:
                report.status = "FAIL"
                report.status_extended = (
                    f"ECR repository {repository.name} has scan on push disabled"
                )

            findings.append(report)

        return findings
