from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecr.ecr_client import ecr_client


class ecr_repositories_lifecycle_policy_enabled(Check):
    def execute(self):
        findings = []
        for registry in ecr_client.registries.values():
            for repository in registry.repositories:
                report = Check_Report_AWS(self.metadata())
                report.region = repository.region
                report.resource_id = repository.name
                report.resource_arn = repository.arn
                report.resource_tags = repository.tags
                report.status = "FAIL"
                report.status_extended = f"Repository {repository.name} does not have a lifecycle policy configured."
                if repository.lifecycle_policy:
                    report.status = "PASS"
                    report.status_extended = f"Repository {repository.name} has a lifecycle policy configured."

                findings.append(report)

        return findings
