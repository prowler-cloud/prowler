from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecr.ecr_client import ecr_client
from prowler.providers.aws.services.iam.lib.policy import is_policy_public


class ecr_repositories_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for registry in ecr_client.registries.values():
            for repository in registry.repositories:
                report = Check_Report_AWS(self.metadata())
                report.region = repository.region
                report.resource_id = repository.name
                report.resource_arn = repository.arn
                report.resource_tags = repository.tags
                report.status = "PASS"
                report.status_extended = (
                    f"Repository {repository.name} is not publicly accessible."
                )
                if repository.policy:
                    if is_policy_public(repository.policy, ecr_client.audited_account):
                        report.status = "FAIL"
                        report.status_extended = (
                            f"Repository {repository.name} is publicly accessible."
                        )

                findings.append(report)

        return findings
