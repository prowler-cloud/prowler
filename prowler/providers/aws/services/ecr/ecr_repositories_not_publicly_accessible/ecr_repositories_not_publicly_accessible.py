from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecr.ecr_client import ecr_client


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
                    f"Repository {repository.name} is not publicly accesible."
                )
                if repository.policy:
                    for statement in repository.policy["Statement"]:
                        if statement["Effect"] == "Allow":
                            if "*" in statement["Principal"] or (
                                "AWS" in statement["Principal"]
                                and "*" in statement["Principal"]["AWS"]
                            ):
                                report.status = "FAIL"
                                report.status_extended = f"Repository {repository.name} policy may allow anonymous users to perform actions (Principal: '*')."
                                break

                findings.append(report)

        return findings
