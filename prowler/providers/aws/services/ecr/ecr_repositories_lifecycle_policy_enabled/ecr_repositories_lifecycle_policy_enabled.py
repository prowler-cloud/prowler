from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecr.ecr_client import ecr_client


class ecr_repositories_lifecycle_policy_enabled(Check):
    def execute(self):
        findings = []
        for repository in ecr_client.repositories:
            report = Check_Report_AWS(self.metadata())
            report.region = repository.region
            report.resource_id = repository.name
            report.resource_arn = repository.arn
            report.status = "FAIL"
            report.status_extended = (
                f"Repository {repository.name} has no lifecycle policy"
            )
            if repository.lyfecicle_policy:
                report.status = "PASS"
                report.status_extended = (
                    f"Repository {repository.name} has lifecycle policy"
                )

            findings.append(report)

        return findings
