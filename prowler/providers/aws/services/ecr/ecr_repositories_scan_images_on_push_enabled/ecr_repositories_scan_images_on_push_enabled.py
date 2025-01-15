from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecr.ecr_client import ecr_client


class ecr_repositories_scan_images_on_push_enabled(Check):
    def execute(self):
        findings = []
        for registry in ecr_client.registries.values():
            for repository in registry.repositories:
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource_metadata=repository
                )
                report.status = "PASS"
                report.status_extended = (
                    f"ECR repository {repository.name} has scan on push enabled."
                )
                if not repository.scan_on_push:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"ECR repository {repository.name} has scan on push disabled."
                    )

                findings.append(report)

        return findings
